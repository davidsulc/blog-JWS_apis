defmodule JwsDemo.JWS.JWKSPublisher do
  @moduledoc """
  Publishes public keys in JWKS (JSON Web Key Set) format.

  JWKS is the standard format for publishing public keys that partners use to
  verify JWS signatures. This module demonstrates:
  - Reading EC public keys from PEM files
  - Converting JOSE.JWK to JWKS format
  - Supporting multiple keys for zero-downtime rotation
  - Proper key metadata (kid, alg, use)

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
  4. After cache TTL expires, remove old key

  This enables zero-downtime key rotation.

  ## Cache Headers

  JWKS endpoint should return:
  - `Cache-Control: public, max-age=600, must-revalidate`
  - 10-minute cache for performance
  - Clients refresh keys before signing

  ## Examples

      # Get current JWKS
      {:ok, jwks} = JWKSPublisher.get_jwks()
      assert %{"keys" => [%{"kid" => "demo-2025-01"}]} = jwks

      # Get JWKS for specific key IDs
      {:ok, jwks} = JWKSPublisher.get_jwks(["demo-2025-01", "demo-2025-02"])

  """

  @doc """
  Returns JWKS for all configured public keys.

  Reads public keys from priv/keys directory and converts to JWKS format.
  """
  @spec get_jwks() :: {:ok, map()} | {:error, term()}
  def get_jwks do
    get_jwks(["demo-2025-01"])
  end

  @doc """
  Returns JWKS for specified key IDs.

  ## Parameters
  - `key_ids` - List of key IDs to include in JWKS

  ## Returns
  - `{:ok, jwks}` - JWKS object with "keys" array
  - `{:error, reason}` - If key loading fails
  """
  @spec get_jwks(list(String.t())) :: {:ok, map()} | {:error, term()}
  def get_jwks(key_ids) do
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

  # Private functions

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
