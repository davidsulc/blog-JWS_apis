defmodule JwsDemo.JWS.JWKSPublisher do
  @moduledoc """
  Publishes public keys in JWKS (JSON Web Key Set) format with in-memory caching.

  JWKS is the standard format for publishing public keys that partners use to
  verify JWS signatures. This module demonstrates:
  - Reading EC public keys from PEM files
  - Converting JOSE.JWK to JWKS format
  - In-memory caching for performance (avoids disk I/O on every request)
  - Supporting multiple keys for zero-downtime rotation
  - Proper key metadata (kid, alg, use)

  ## Performance

  Keys are loaded from disk once on GenServer startup and cached in process state.
  Subsequent requests return cached JWKS immediately (~microseconds vs ~milliseconds
  for file I/O + PEM parsing).

  ## JWKS Format

  Returns JSON object with "keys" array:
  ```json
  {
    "keys": [
      {
        "kty": "EC",
        "use": "sig",
        "kid": "demo-2025-01",
        "alg": "ES256",
        "crv": "P-256",
        "x": "gfCoE4Yhm3NLOYuXasD_E3VqexZshc2o3z6eQ6-1c-4",
        "y": "C86t3ZhtQ1RL1ifFn_pwYakgAPpQoY_IU3-V0CeXgKQ"
      }
    ]
  }
  ```

  ## Key Rotation

  Multiple keys can be published simultaneously:
  1. Publish new key (kid: "2025-02") alongside old key (kid: "2025-01")
  2. Partners cache both keys
  3. Start signing with new key
  4. Call `reload_keys/0` to refresh the cache
  5. After partner cache TTL expires, remove old key

  This enables zero-downtime key rotation.

  ## Cache Headers

  JWKS endpoint should return:
  - `Cache-Control: public, max-age=600, must-revalidate`
  - 10-minute cache for performance
  - Clients refresh keys before signing

  ## Examples

      # Get current JWKS (from cache)
      {:ok, jwks} = JWKSPublisher.get_jwks()
      assert %{"keys" => [%{"kid" => "demo-2025-01"}]} = jwks

      # Reload keys after rotation
      :ok = JWKSPublisher.reload_keys()

  """

  use GenServer
  require Logger

  # Client API

  @doc """
  Starts the JWKS publisher GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Returns JWKS for all configured public keys.

  Returns cached JWKS from GenServer state (fast, no disk I/O).
  """
  @spec get_jwks() :: {:ok, map()} | {:error, term()}
  def get_jwks do
    GenServer.call(__MODULE__, :get_jwks)
  end

  @doc """
  Reloads keys from disk and updates cache.

  Call this after key rotation to refresh the published JWKS.
  """
  @spec reload_keys() :: :ok
  def reload_keys do
    GenServer.cast(__MODULE__, :reload_keys)
  end

  # Server Callbacks

  @impl true
  def init(_opts) do
    # Return immediately to avoid blocking supervisor startup
    # Load keys asynchronously via handle_continue
    {:ok, %{jwks: %{"keys" => []}}, {:continue, :load_keys}}
  end

  @impl true
  def handle_continue(:load_keys, state) do
    # Load keys asynchronously after init completes
    Logger.info("JWKS publisher loading keys asynchronously")

    case load_all_keys() do
      {:ok, jwks} ->
        Logger.info("JWKS publisher loaded #{length(jwks["keys"])} keys")
        {:noreply, %{state | jwks: jwks}}

      {:error, reason} ->
        Logger.error("JWKS publisher failed to load keys: #{inspect(reason)}")
        # Keep empty JWKS on load failure
        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:get_jwks, _from, state) do
    {:reply, {:ok, state.jwks}, state}
  end

  @impl true
  def handle_cast(:reload_keys, state) do
    Logger.info("JWKS publisher reloading keys")

    case load_all_keys() do
      {:ok, jwks} ->
        Logger.info("JWKS publisher reloaded #{length(jwks["keys"])} keys")
        {:noreply, %{state | jwks: jwks}}

      {:error, reason} ->
        Logger.error("JWKS publisher failed to reload keys: #{inspect(reason)}")
        # Keep existing cache on reload failure
        {:noreply, state}
    end
  end

  # Private functions

  # Load all configured keys from disk
  defp load_all_keys do
    # In production, query database for list of active key IDs
    # For demo, use hardcoded list
    key_ids = ["demo-2025-01"]

    keys =
      Enum.map(key_ids, fn kid ->
        case load_public_key(kid) do
          {:ok, jwk} ->
            jwk_to_jwks_entry(jwk, kid)

          {:error, _reason} ->
            # Skip keys that fail to load (allows graceful degradation)
            nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    case keys do
      [] -> {:error, :no_keys_available}
      keys -> {:ok, %{"keys" => keys}}
    end
  end

  # Load public key from PEM file
  defp load_public_key(kid) do
    # Map kid to file path
    # In production, this would come from database or key management service
    key_path = get_key_path(kid)

    case File.read(key_path) do
      {:ok, pem_content} ->
        jwk = JOSE.JWK.from_pem(pem_content)
        {:ok, jwk}

      {:error, reason} ->
        {:error, {:file_read_failed, reason}}
    end
  rescue
    error -> {:error, {:jwk_parse_failed, error}}
  end

  # Map kid to file path
  defp get_key_path("demo-2025-01") do
    Path.join(:code.priv_dir(:jws_demo), "keys/demo_public_key.pem")
  end

  defp get_key_path(_kid) do
    # Return default path for unknown kids
    # In production, query database for key path
    Path.join(:code.priv_dir(:jws_demo), "keys/demo_public_key.pem")
  end

  # Convert JOSE.JWK to JWKS entry format
  defp jwk_to_jwks_entry(jwk, kid) do
    # Convert JWK to map
    jwk_map = JOSE.JWK.to_map(jwk) |> elem(1)

    # Build JWKS entry with standard fields
    %{
      "kty" => jwk_map["kty"],
      "use" => "sig",
      "kid" => kid,
      "alg" => "ES256",
      "crv" => jwk_map["crv"],
      "x" => jwk_map["x"],
      "y" => jwk_map["y"]
    }
  end

  @doc """
  Validates that a JWKS entry has all required fields.

  Used for testing and validation.
  """
  @spec valid_jwks_entry?(map()) :: boolean()
  def valid_jwks_entry?(entry) do
    required_fields = ["kty", "use", "kid", "alg", "crv", "x", "y"]

    Enum.all?(required_fields, fn field ->
      Map.has_key?(entry, field) and is_binary(entry[field]) and entry[field] != ""
    end)
  end
end
