defmodule JwsDemo.JWS.JWKSCache do
  @moduledoc """
  Multi-tenant JWKS caching with stale-while-revalidate strategy.

  This GenServer demonstrates:
  - Per-partner JWKS caching for performance
  - TTL-based expiration (respects Cache-Control max-age, 15 minutes default)
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

  import Ecto.Query
  alias JwsDemo.Repo
  alias JwsDemo.Partners.Partner

  # 15 minutes
  @default_ttl 900
  # 24 hours
  @stale_grace_period 86_400
  @table_name :jwks_cache
  # Demo mode: set to false in production to enable real JWKS fetching
  @demo_mode Application.compile_env(:jws_demo, :jwks_demo_mode, true)
  # DoS protection: debounce window for unknown kid refreshes
  @unknown_kid_debounce_seconds 60
  # DoS protection: max unknown kid attempts per minute
  @unknown_kid_rate_limit 10
  # DoS protection: circuit breaker threshold
  @circuit_breaker_threshold 5

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

  @doc """
  Immediately purges JWKS cache for a partner during security incidents.

  Use when partner confirms:
  - Private key compromise
  - Security breach
  - Unauthorized access

  This forces fresh JWKS fetch on next request. If fetch fails,
  requests return 401 until JWKS is successfully retrieved.

  ## Authorization Required
  - Senior ops approval
  - Incident ticket reference
  - Business justification

  ## Audit Trail
  All purges logged with timestamp, operator, and reason.

  ## Parameters
  - `partner_id` - Partner identifier to purge
  - `operator` - Name/ID of person executing purge
  - `reason` - Business justification (incident ticket, etc.)

  ## Examples

      JWKSCache.emergency_purge(
        "partner_abc",
        "ops.alice@example.com",
        "INC-2025-001: Partner confirmed private key compromise"
      )

  """
  @spec emergency_purge(String.t(), String.t(), String.t()) :: :ok
  def emergency_purge(partner_id, operator, reason) do
    GenServer.call(__MODULE__, {:emergency_purge, partner_id, operator, reason})
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
  def handle_call({:emergency_purge, partner_id, operator, reason}, _from, state) do
    Logger.warning("""
    🚨 EMERGENCY JWKS CACHE PURGE
    Partner: #{partner_id}
    Operator: #{operator}
    Reason: #{reason}
    Timestamp: #{DateTime.utc_now() |> DateTime.to_iso8601()}
    """)

    # Count keys being purged for logging
    purged_count =
      :ets.select_delete(@table_name, [
        {{{:"$1", :_}, :_, :_, :_}, [{:==, :"$1", partner_id}], [true]}
      ])

    Logger.warning("Purged #{purged_count} keys for partner: #{partner_id}")

    # Emit telemetry event for monitoring
    :telemetry.execute(
      [:jwks_cache, :emergency_purge],
      %{purged_keys: purged_count},
      %{partner_id: partner_id, operator: operator, reason: reason}
    )

    # Log to audit trail (structured log that can be ingested by SIEM)
    log_cache_purge(partner_id, operator, reason, purged_count)

    {:reply, :ok, state}
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
            # Reset consecutive unknown kids counter on successful cache hit
            reset_unknown_kid_counter(partner_id)
            {:reply, {:ok, jwk}, state}

          # Stale but within grace period: return stale + trigger refresh
          age < @stale_grace_period ->
            # Alert ops team with severity based on cache age
            alert_stale_cache(partner_id, kid, age, cached_at)

            Logger.warning(
              "JWKS cache HIT (stale): #{partner_id}/#{kid}, age: #{age}s, triggering refresh"
            )

            # Trigger background refresh (don't block)
            GenServer.cast(self(), {:refresh, partner_id})

            # Reset consecutive unknown kids counter
            reset_unknown_kid_counter(partner_id)

            {:reply, {:ok, jwk}, state}

          # Too stale: force refresh
          true ->
            Logger.warning("JWKS cache MISS (too stale): #{partner_id}/#{kid}, age: #{age}s")
            handle_cache_miss_with_protection(partner_id, kid, state)
        end

      [] ->
        # Not in cache: unknown kid - apply DoS protection
        Logger.info("JWKS cache MISS (unknown kid): #{partner_id}/#{kid}")
        handle_cache_miss_with_protection(partner_id, kid, state)
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

    # Fetch all active partners from database
    # Handle database connection errors gracefully (e.g., during test startup)
    partners =
      try do
        Repo.all(
          from p in Partner,
            where: p.active == true,
            preload: [:config]
        )
      rescue
        error ->
          Logger.warning("JWKS cache warming: database not available (#{inspect(error)})")
          []
      end

    Logger.info("Found #{length(partners)} active partners to warm cache")

    # Attempt to fetch JWKS for each partner
    results =
      Enum.map(partners, fn partner ->
        case fetch_and_cache_jwks(partner.partner_id) do
          :ok ->
            Logger.info("JWKS cache warmed successfully: #{partner.partner_id}")
            {:ok, partner.partner_id}

          {:error, reason} ->
            Logger.warning(
              "JWKS cache warming failed for #{partner.partner_id}: #{inspect(reason)}"
            )

            {:error, partner.partner_id, reason}
        end
      end)

    success_count = Enum.count(results, fn r -> match?({:ok, _}, r) end)
    failure_count = length(results) - success_count

    Logger.info(
      "JWKS cache warming complete: #{success_count} succeeded, #{failure_count} failed"
    )

    {:noreply, state}
  end

  # Private functions

  # Handle cache miss with DoS protection for unknown kid
  defp handle_cache_miss_with_protection(partner_id, kid, state) do
    now = System.system_time(:second)

    # Check 1: Circuit breaker (too many consecutive unknown kids)
    case check_circuit_breaker(partner_id) do
      {:error, :circuit_breaker_open} = error ->
        Logger.error(
          "Circuit breaker OPEN for #{partner_id}: Too many consecutive unknown kids. " <>
            "Rejecting request for kid: #{kid}"
        )

        {:reply, error, state}

      :ok ->
        # Check 2: Rate limiting (too many unknown kid attempts per minute)
        case check_unknown_kid_rate_limit(partner_id, now) do
          {:error, :rate_limited} = error ->
            Logger.error(
              "Rate limit EXCEEDED for #{partner_id}: Too many unknown kid attempts. " <>
                "Rejecting request for kid: #{kid}"
            )

            {:reply, error, state}

          :ok ->
            # Check 3: Debouncing (did we recently fetch JWKS for this partner?)
            case check_recent_fetch(partner_id, now) do
              {:debounced, age} ->
                # We fetched JWKS recently but kid still not found
                Logger.warning(
                  "Unknown kid #{kid} for #{partner_id}, but JWKS fetched #{age}s ago. " <>
                    "Kid truly doesn't exist. Possible attack or misconfiguration."
                )

                # Emit telemetry for attack detection
                :telemetry.execute(
                  [:jwks_cache, :unknown_kid_rejected],
                  %{age_since_fetch: age},
                  %{partner_id: partner_id, kid: kid}
                )

                # Increment unknown kid counter (for circuit breaker)
                increment_unknown_kid_counter(partner_id)

                {:reply, {:error, :kid_not_found_in_jwks}, state}

              :ok ->
                # No recent fetch - safe to refresh
                Logger.info(
                  "Unknown kid #{kid} for #{partner_id}, fetching fresh JWKS (debounce check passed)"
                )

                handle_cache_miss(partner_id, kid, state, now)
            end
        end
    end
  end

  # Handle cache miss by fetching JWKS (original logic, now with metadata update)
  defp handle_cache_miss(partner_id, kid, state, now) do

    case fetch_and_cache_jwks(partner_id, now) do
      :ok ->
        # Retry lookup after caching
        case :ets.lookup(@table_name, {partner_id, kid}) do
          [{_, jwk, _, _}] ->
            # Success: reset unknown kid counter
            reset_unknown_kid_counter(partner_id)
            {:reply, {:ok, jwk}, state}

          [] ->
            # Kid still not found after fresh fetch
            increment_unknown_kid_counter(partner_id)
            {:reply, {:error, :kid_not_found_in_jwks}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  # Fetch JWKS from partner endpoint and cache all keys
  defp fetch_and_cache_jwks(partner_id, now \\ nil) do
    now = now || System.system_time(:second)

    # Get partner's JWKS URL from config/database
    # For demo, use a mock JWKS URL
    case get_partner_jwks_url(partner_id) do
      {:ok, jwks_url} ->
        case fetch_jwks(jwks_url) do
          {:ok, jwks, ttl} ->
            # NOTE: In demo mode, fetch_jwks always returns error, so this branch is unreachable.
            # In production, this would cache the successfully fetched JWKS.
            result = cache_jwks(partner_id, jwks, ttl)

            # Update metadata: successful fetch
            update_partner_metadata(partner_id, now, true)

            result

          {:error, reason} ->
            # Update metadata: failed fetch
            update_partner_metadata(partner_id, now, false)
            {:error, {:jwks_fetch_failed, reason}}
        end

      {:error, reason} ->
        # Update metadata: failed fetch (partner not found)
        update_partner_metadata(partner_id, now, false)
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
        {:ok, %Req.Response{status: 200, body: jwks, headers: headers}} when is_map(jwks) ->
          # Extract TTL from Cache-Control header, fallback to default
          ttl =
            case parse_cache_control_ttl(headers) do
              {:ok, ttl} -> ttl
              _ -> @default_ttl
            end

          {:ok, jwks, ttl}

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
  defp cache_jwks(partner_id, jwks, ttl) do
    now = System.system_time(:second)

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

              Logger.debug("Cached JWKS key: #{partner_id}/#{kid} (TTL: #{ttl}s)")

            _ ->
              Logger.warning("JWKS key missing kid: #{inspect(key)}")
          end
        end)

        :ok

      _ ->
        {:error, :invalid_jwks_format}
    end
  end

  # Parse TTL from Cache-Control header
  @doc false
  def parse_cache_control_ttl(headers) do
    with {:ok, cache_control} <- find_cache_control_header(headers),
        {:ok, ttl} <- parse_max_age(cache_control) do
      {:ok, ttl}
    else
      _ -> {:error, :no_valid_ttl}
    end
  end

  # Find Cache-Control header value (case-insensitive)
  defp find_cache_control_header(headers) do
    case Enum.find_value(headers, fn {key, value} ->
           if String.downcase(key) == "cache-control", do: value
         end) do
      nil -> {:error, :not_found}
      value -> {:ok, value}
    end
  end

  # Parse max-age directive from Cache-Control value
  defp parse_max_age(cache_control) when is_binary(cache_control) do
    with {:ok, max_age_directive} <- find_max_age_directive(cache_control) do
      parse_ttl(max_age_directive)
    end
  end

  defp parse_max_age(_), do: {:error, :invalid_input}

  # Find max-age directive from Cache-Control directives
  defp find_max_age_directive(cache_control) do
    directive =
      cache_control
      |> String.split(",", trim: true)
      # |> Enum.find(&Regex.match?(~r/^\s*max-age=/i, &1))
      |> Enum.find(& &1 |> String.trim_leading() |> String.starts_with?("max-age="))

    case directive do
      nil -> {:error, :not_found}
      directive -> {:ok, String.trim(directive)}
    end
  end

  # Parse TTL value from max-age directive
  defp parse_ttl("max-age=" <> ttl_string) do
    with {ttl, ""} when ttl > 0 <- Integer.parse(ttl_string) do
      {:ok, ttl}
    else
      _ -> {:error, :invalid_format}
    end
  end

  # Alert ops when cache enters stale grace period
  defp alert_stale_cache(partner_id, kid, age_seconds, cached_at) do
    # Calculate severity based on age
    severity =
      cond do
        age_seconds < 3600 -> :warning
        age_seconds < 14_400 -> :error
        age_seconds < 43_200 -> :critical
        true -> :emergency
      end

    # Emit telemetry for monitoring/alerting systems
    :telemetry.execute(
      [:jwks_cache, :stale_grace_period],
      %{age_seconds: age_seconds},
      %{
        partner_id: partner_id,
        kid: kid,
        severity: severity,
        cached_at: cached_at
      }
    )

    # Structured log for SIEM ingestion
    if severity in [:critical, :emergency] do
      Logger.log(severity, """
      ⚠️  JWKS CACHE STALE GRACE PERIOD ACTIVE
      Partner: #{partner_id}
      Key ID: #{kid}
      Cache age: #{format_duration(age_seconds)}
      Severity: #{severity}
      Last cached: #{format_timestamp(cached_at)}

      ACTION REQUIRED:
      1. Contact partner security team (out-of-band)
      2. Verify JWKS endpoint status
      3. Confirm no security incident
      4. If key compromise confirmed: JWKSCache.emergency_purge("#{partner_id}", "your_name", "reason")
      """)
    end
  end

  # Log cache purge to audit trail
  defp log_cache_purge(partner_id, operator, reason, purged_count) do
    # Structured log for audit trail (ingested by SIEM/log aggregation)
    Logger.warning(
      "JWKS cache emergency purge executed",
      event: "jwks_cache_purge",
      partner_id: partner_id,
      operator: operator,
      reason: reason,
      purged_keys: purged_count,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    )

    # In production, also write to dedicated audit table:
    # Audit.log_operational_event(%{
    #   event_type: "jwks_cache_purge",
    #   partner_id: partner_id,
    #   operator: operator,
    #   reason: reason,
    #   metadata: %{purged_keys: purged_count}
    # })
  end

  # Format duration in human-readable form
  defp format_duration(seconds) when seconds < 60, do: "#{seconds}s"
  defp format_duration(seconds) when seconds < 3600, do: "#{div(seconds, 60)}m"
  defp format_duration(seconds) when seconds < 86_400, do: "#{div(seconds, 3600)}h"
  defp format_duration(seconds), do: "#{div(seconds, 86_400)}d #{rem(div(seconds, 3600), 24)}h"

  # Format unix timestamp to ISO8601
  defp format_timestamp(unix_seconds) do
    unix_seconds
    |> DateTime.from_unix!()
    |> DateTime.to_iso8601()
  end

  # DoS Protection: Partner Metadata Management

  # Check if we recently fetched JWKS for this partner (debouncing)
  defp check_recent_fetch(partner_id, now) do
    metadata_key = {partner_id, :metadata}

    case :ets.lookup(@table_name, metadata_key) do
      [{^metadata_key, metadata}] ->
        age = now - metadata.last_fetch_at

        if age < @unknown_kid_debounce_seconds do
          {:debounced, age}
        else
          :ok
        end

      [] ->
        :ok
    end
  end

  # Check circuit breaker status (too many consecutive unknown kids)
  defp check_circuit_breaker(partner_id) do
    metadata_key = {partner_id, :metadata}

    case :ets.lookup(@table_name, metadata_key) do
      [{^metadata_key, metadata}] ->
        if metadata.consecutive_unknown_kids >= @circuit_breaker_threshold do
          # Emit telemetry for circuit breaker
          :telemetry.execute(
            [:jwks_cache, :circuit_breaker_open],
            %{consecutive_unknown_kids: metadata.consecutive_unknown_kids},
            %{partner_id: partner_id}
          )

          {:error, :circuit_breaker_open}
        else
          :ok
        end

      [] ->
        :ok
    end
  end

  # Check unknown kid rate limit
  defp check_unknown_kid_rate_limit(partner_id, now) do
    rate_limit_key = {partner_id, :rate_limit}
    window = 60

    case :ets.lookup(@table_name, rate_limit_key) do
      [{^rate_limit_key, count, window_start}] when now - window_start < window ->
        if count >= @unknown_kid_rate_limit do
          # Emit telemetry for rate limit
          :telemetry.execute(
            [:jwks_cache, :rate_limit_exceeded],
            %{attempts: count},
            %{partner_id: partner_id}
          )

          {:error, :rate_limited}
        else
          # Increment counter
          :ets.update_counter(@table_name, rate_limit_key, {2, 1})
          :ok
        end

      _ ->
        # Start new window
        :ets.insert(@table_name, {rate_limit_key, 1, now})
        :ok
    end
  end

  # Update partner metadata after JWKS fetch
  defp update_partner_metadata(partner_id, fetch_time, success) do
    metadata_key = {partner_id, :metadata}

    metadata =
      case :ets.lookup(@table_name, metadata_key) do
        [{^metadata_key, existing}] ->
          %{
            existing
            | last_fetch_at: fetch_time,
              last_fetch_success: success
          }

        [] ->
          %{
            last_fetch_at: fetch_time,
            last_fetch_success: success,
            consecutive_unknown_kids: 0
          }
      end

    :ets.insert(@table_name, {metadata_key, metadata})
  end

  # Increment consecutive unknown kid counter
  defp increment_unknown_kid_counter(partner_id) do
    metadata_key = {partner_id, :metadata}

    case :ets.lookup(@table_name, metadata_key) do
      [{^metadata_key, metadata}] ->
        new_count = metadata.consecutive_unknown_kids + 1

        updated_metadata = %{metadata | consecutive_unknown_kids: new_count}
        :ets.insert(@table_name, {metadata_key, updated_metadata})

        # Emit telemetry for monitoring
        :telemetry.execute(
          [:jwks_cache, :unknown_kid_incremented],
          %{consecutive_count: new_count},
          %{partner_id: partner_id}
        )

      [] ->
        # Create new metadata entry
        metadata = %{
          last_fetch_at: 0,
          last_fetch_success: false,
          consecutive_unknown_kids: 1
        }

        :ets.insert(@table_name, {metadata_key, metadata})
    end
  end

  # Reset consecutive unknown kid counter
  defp reset_unknown_kid_counter(partner_id) do
    metadata_key = {partner_id, :metadata}

    case :ets.lookup(@table_name, metadata_key) do
      [{^metadata_key, metadata}] ->
        if metadata.consecutive_unknown_kids > 0 do
          updated_metadata = %{metadata | consecutive_unknown_kids: 0}
          :ets.insert(@table_name, {metadata_key, updated_metadata})

          Logger.debug("Reset unknown kid counter for #{partner_id}")
        end

      [] ->
        :ok
    end
  end
end
