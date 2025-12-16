defmodule JwsDemo.JWS.JWKSCache do
  @moduledoc """
  Multi-tenant JWKS caching with stale-while-revalidate strategy.

  This GenServer demonstrates:
  - Per-partner JWKS caching for performance
  - TTL-based expiration (15 minutes default)
  - Stale-while-revalidate pattern for zero-downtime
  - Graceful degradation when JWKS fetch fails
  - ETS storage for concurrent reads

  ## Caching Strategy

  **Fresh Cache (within TTL):**
  - Return cached key immediately (~100μs)
  - No network request needed

  **Stale Cache (expired but within grace period):**
  - Return stale key immediately (don't block)
  - Trigger background refresh for next request
  - Grace period: 24 hours (allows partner endpoint outages)

  **Missing/Unknown kid:**
  - Trigger immediate JWKS refresh
  - If refresh fails, return error
  - Prevents verification with wrong key

  ## Performance

  - Cache hit: ~100μs (ETS lookup)
  - Cache miss: ~50-200ms (HTTP fetch + parse)
  - 100-2000x improvement with caching

  ## Zero-Downtime Rotation

  1. Partner adds new key to JWKS (both old and new present)
  2. Cache refresh fetches both keys
  3. Partner starts signing with new key
  4. Old signatures still verify (old key still cached)
  5. After rotation period, partner removes old key

  ## Examples

      # Get key for verification
      {:ok, jwk} = JWKSCache.get_key("partner_abc", "2025-01-key")

      # Force refresh
      :ok = JWKSCache.refresh("partner_abc")

      # Warm cache on startup
      :ok = JWKSCache.warm_cache()

  """

  use GenServer
  require Logger

  # 15 minutes
  @default_ttl 900
  # 24 hours
  @stale_grace_period 86_400
  @table_name :jwks_cache
  # Demo mode: set to false in production to enable real JWKS fetching
  @demo_mode Application.compile_env(:jws_demo, :jwks_demo_mode, true)

  # Client API

  @doc """
  Starts the JWKS cache GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Gets a JWK for a specific partner and key ID.

  Returns cached key if available and fresh, otherwise fetches from partner's JWKS endpoint.

  ## Parameters
  - `partner_id` - Partner identifier
  - `kid` - Key ID to retrieve

  ## Returns
  - `{:ok, jwk}` - JWK for verification
  - `{:error, reason}` - If key not found or fetch fails
  """
  @spec get_key(String.t(), String.t()) :: {:ok, JOSE.JWK.t()} | {:error, term()}
  def get_key(partner_id, kid) do
    GenServer.call(__MODULE__, {:get_key, partner_id, kid})
  end

  @doc """
  Forces a refresh of partner's JWKS.

  Useful for manual key rotation or debugging.
  """
  @spec refresh(String.t()) :: :ok
  def refresh(partner_id) do
    GenServer.cast(__MODULE__, {:refresh, partner_id})
  end

  @doc """
  Warms the cache by preloading all partners' JWKS.

  Should be called on application startup.
  """
  @spec warm_cache() :: :ok
  def warm_cache do
    GenServer.cast(__MODULE__, :warm_cache)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Create ETS table for concurrent reads
    table = :ets.new(@table_name, [:set, :public, :named_table, read_concurrency: true])

    Logger.info("JWKS cache started with ETS table: #{@table_name}")

    {:ok, %{table: table}}
  end

  @impl true
  def handle_call({:get_key, partner_id, kid}, _from, state) do
    cache_key = {partner_id, kid}

    case :ets.lookup(@table_name, cache_key) do
      [{^cache_key, jwk, cached_at, ttl}] ->
        now = System.system_time(:second)
        age = now - cached_at

        cond do
          # Fresh cache: return immediately
          age < ttl ->
            Logger.debug("JWKS cache HIT (fresh): #{partner_id}/#{kid}, age: #{age}s")
            {:reply, {:ok, jwk}, state}

          # Stale but within grace period: return stale + trigger refresh
          age < @stale_grace_period ->
            Logger.warning(
              "JWKS cache HIT (stale): #{partner_id}/#{kid}, age: #{age}s, triggering refresh"
            )

            # Trigger background refresh (don't block)
            GenServer.cast(self(), {:refresh, partner_id})

            {:reply, {:ok, jwk}, state}

          # Too stale: force refresh
          true ->
            Logger.warning("JWKS cache MISS (too stale): #{partner_id}/#{kid}, age: #{age}s")
            handle_cache_miss(partner_id, kid, state)
        end

      [] ->
        # Not in cache: fetch from JWKS endpoint
        Logger.info("JWKS cache MISS: #{partner_id}/#{kid}")
        handle_cache_miss(partner_id, kid, state)
    end
  end

  @impl true
  def handle_cast({:refresh, partner_id}, state) do
    Logger.info("JWKS cache refresh requested: #{partner_id}")

    case fetch_and_cache_jwks(partner_id) do
      :ok ->
        Logger.info("JWKS cache refresh successful: #{partner_id}")

      {:error, reason} ->
        Logger.error("JWKS cache refresh failed: #{partner_id}, reason: #{inspect(reason)}")
    end

    {:noreply, state}
  end

  @impl true
  def handle_cast(:warm_cache, state) do
    Logger.info("JWKS cache warming started")

    # In production, fetch list of partners from database
    # For demo, we'll just log
    Logger.info("JWKS cache warming complete (demo: no partners configured)")

    {:noreply, state}
  end

  # Private functions

  # Handle cache miss by fetching JWKS
  defp handle_cache_miss(partner_id, kid, state) do
    case fetch_and_cache_jwks(partner_id) do
      :ok ->
        # Retry lookup after caching
        case :ets.lookup(@table_name, {partner_id, kid}) do
          [{_, jwk, _, _}] ->
            {:reply, {:ok, jwk}, state}

          [] ->
            {:reply, {:error, :kid_not_found_in_jwks}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  # Fetch JWKS from partner endpoint and cache all keys
  defp fetch_and_cache_jwks(partner_id) do
    # Get partner's JWKS URL from config/database
    # For demo, use a mock JWKS URL
    case get_partner_jwks_url(partner_id) do
      {:ok, jwks_url} ->
        case fetch_jwks(jwks_url) do
          {:ok, jwks} ->
            # NOTE: In demo mode, fetch_jwks always returns error, so this branch is unreachable.
            # In production, this would cache the successfully fetched JWKS.
            cache_jwks(partner_id, jwks)

          {:error, reason} ->
            {:error, {:jwks_fetch_failed, reason}}
        end

      {:error, reason} ->
        {:error, {:partner_not_found, reason}}
    end
  end

  # Get partner's JWKS URL
  defp get_partner_jwks_url(partner_id) do
    # In production: query database
    # For demo: return mock URL or error
    case partner_id do
      "partner_abc" ->
        # Mock: partner has a JWKS endpoint
        {:ok, "https://partner-abc.example.com/.well-known/jwks.json"}

      _ ->
        {:error, :partner_not_configured}
    end
  end

  # Fetch JWKS from URL
  defp fetch_jwks(jwks_url) do
    if @demo_mode do
      # Demo mode: don't make real HTTP requests
      Logger.debug("Demo mode: Would fetch JWKS from: #{jwks_url}")
      {:error, :demo_mode_no_real_fetch}
    else
      # Production mode: fetch JWKS via HTTP using Req
      case Req.get(jwks_url,
             receive_timeout: 5000,
             retry: :transient,
             max_retries: 2
           ) do
        {:ok, %Req.Response{status: 200, body: jwks}} when is_map(jwks) ->
          {:ok, jwks}

        {:ok, %Req.Response{status: status}} ->
          {:error, {:http_status, status}}

        {:error, error} ->
          {:error, {:http_error, error}}
      end
    end
  rescue
    error -> {:error, {:http_error, error}}
  end

  # Cache all keys from JWKS
  defp cache_jwks(partner_id, jwks) do
    now = System.system_time(:second)
    ttl = @default_ttl

    # Parse JWKS and cache each key
    case jwks do
      %{"keys" => keys} when is_list(keys) ->
        Enum.each(keys, fn key ->
          case key do
            %{"kid" => kid} = jwk_map ->
              # Convert to JOSE.JWK
              jwk = JOSE.JWK.from(jwk_map)

              # Cache with TTL
              cache_key = {partner_id, kid}
              :ets.insert(@table_name, {cache_key, jwk, now, ttl})

              Logger.debug("Cached JWKS key: #{partner_id}/#{kid}")

            _ ->
              Logger.warning("JWKS key missing kid: #{inspect(key)}")
          end
        end)

        :ok

      _ ->
        {:error, :invalid_jwks_format}
    end
  end
end
