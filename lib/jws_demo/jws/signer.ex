defmodule JwsDemo.JWS.Signer do
  @moduledoc """
  Signs payloads using ES256 (ECDSA with P-256 curve) with JWS.

  Supports both flattened JSON and compact serialization formats.
  Demonstrates concepts from Blog Post 2: Implementation with Elixir/JOSE.

  ## Serialization Formats

  ### Flattened JSON (Recommended for Authorization Messages)
  More readable, better for request bodies, easier to debug:
  ```
  %{
    "payload" => "eyJhbW91bnQ...",
    "protected" => "eyJhbGciOiJFUzI1NiJ9",
    "signature" => "M EUCIQ..."
  }
  ```

  ### Compact (For HTTP Headers, Tokens)
  Smaller size, suitable for Authorization headers:
  ```
  "eyJhbGciOiJFUzI1NiJ9.eyJhbW91bnQ...MEUCIQDEx..."
  ```

  ## Automatic Claims

  The signer automatically includes:
  - `iat` (issued at): Current timestamp
  - `exp` (expiration): `iat + exp_seconds` (default 300s / 5 minutes)
  - `jti` (JWT ID): Unique identifier for replay protection

  ## Canonical JSON Encoding

  Uses `Jason.encode!/2` with `pretty: false` to ensure consistent JSON formatting.
  This is critical for re-verification: different whitespace = different signature.

  ## Examples

      iex> {public, private} = :crypto.generate_key(:ecdh, :secp256r1)
      iex> jwk = JOSE.JWK.from_key({:ECPrivateKey, private, {public, {:namedCurve, :secp256r1}}})
      iex> payload = %{"amount" => 50_000, "currency" => "EUR"}
      iex> {:ok, jws} = JwsDemo.JWS.Signer.sign_flattened(payload, jwk, kid: "demo-key")
      iex> Map.keys(jws)
      ["payload", "protected", "signature"]

  """

  @doc """
  Signs a payload with flattened JSON serialization.

  Returns a map with `payload`, `protected`, and `signature` keys (Base64URL-encoded).

  ## Options

  - `:kid` (required) - Key ID for key rotation support
  - `:exp_seconds` (default: 300) - Token expiration in seconds from now

  ## Examples

      {:ok, jws} = sign_flattened(
        %{"instruction_id" => "txn_123", "amount" => 50_000},
        private_key,
        kid: "2025-01-15"
      )

  """
  @spec sign_flattened(map(), JOSE.JWK.t(), keyword()) :: {:ok, map()} | {:error, term()}
  def sign_flattened(payload, jwk, opts \\ []) do
    kid = Keyword.fetch!(opts, :kid)
    exp_seconds = Keyword.get(opts, :exp_seconds, 300)

    enriched_payload = enrich_payload(payload, exp_seconds)

    # Create protected header
    protected = %{
      "alg" => "ES256",
      "typ" => "JWT",
      "kid" => kid
    }

    # Sign with flattened JSON serialization
    # Use canonical JSON encoding (no pretty printing, no whitespace variation)
    payload_json = Jason.encode!(enriched_payload, pretty: false)

    # Sign and get flattened JSON map
    {%{}, jws_map} =
      JOSE.JWS.sign(jwk, payload_json, protected)
      |> JOSE.JWS.compact()

    # Convert compact to flattened JSON structure
    [header_b64, payload_b64, signature_b64] = String.split(jws_map, ".")

    flattened = %{
      "payload" => payload_b64,
      "protected" => header_b64,
      "signature" => signature_b64
    }

    {:ok, flattened}
  rescue
    error -> {:error, error}
  end

  @doc """
  Signs a payload with compact serialization (dot-separated format).

  Returns a string: `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)`

  Suitable for Authorization headers or URL parameters.

  ## Examples

      {:ok, compact_jws} = sign_compact(
        %{"instruction_id" => "txn_123"},
        private_key,
        kid: "2025-01-15"
      )
      # => "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjIwMjUtMDEtMTUifQ..."

  """
  @spec sign_compact(map(), JOSE.JWK.t(), keyword()) :: {:ok, String.t()} | {:error, term()}
  def sign_compact(payload, jwk, opts \\ []) do
    kid = Keyword.fetch!(opts, :kid)
    exp_seconds = Keyword.get(opts, :exp_seconds, 300)

    enriched_payload = enrich_payload(payload, exp_seconds)

    # Create protected header
    protected = %{
      "alg" => "ES256",
      "typ" => "JWT",
      "kid" => kid
    }

    # Sign with compact serialization
    payload_json = Jason.encode!(enriched_payload, pretty: false)

    {_alg, compact_jws} =
      JOSE.JWS.sign(jwk, payload_json, protected)
      |> JOSE.JWS.compact()

    {:ok, compact_jws}
  rescue
    error -> {:error, error}
  end

  # Private functions

  # Enriches payload with automatic claims (iat, exp, jti)
  defp enrich_payload(payload, exp_seconds) do
    now = System.system_time(:second)

    payload
    |> Map.put("iat", now)
    |> Map.put("exp", now + exp_seconds)
    |> Map.put("jti", UUID.uuid4())
  end
end
