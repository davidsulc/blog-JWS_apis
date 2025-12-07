defmodule JwsDemoWeb.JWKSController do
  @moduledoc """
  JWKS (JSON Web Key Set) endpoint controller.

  Publishes public keys for partners to verify our JWS signatures.

  ## Purpose

  This endpoint demonstrates:
  - Publishing public keys in standard JWKS format (RFC 7517)
  - Proper cache headers for performance
  - Support for key rotation with multiple active keys
  - Zero-downtime key rotation strategy

  ## Endpoint

  `GET /.well-known/jwks.json`

  This is the standard location for JWKS endpoints per RFC 8414.

  ## Response Format

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

  ## Cache Headers

  Returns `Cache-Control: public, max-age=600, must-revalidate`
  - 10-minute cache reduces load
  - Partners refresh keys periodically
  - Must-revalidate ensures fresh keys after rotation

  ## Key Rotation

  During rotation, multiple keys are published:
  1. Add new key to JWKS (both old and new keys present)
  2. Wait for cache TTL to expire (10 minutes)
  3. Start signing with new key
  4. After rotation period, remove old key from JWKS

  ## Examples

      # Fetch JWKS
      curl https://api.example.com/.well-known/jwks.json

      # Cache hit reduces server load
      # Partners fetch once per cache TTL (10 minutes)

  """

  use JwsDemoWeb, :controller
  require Logger

  alias JwsDemo.JWS.JWKSPublisher

  @doc """
  Returns JWKS for all active public keys.

  Sets proper cache headers for performance and key rotation.
  """
  def index(conn, _params) do
    case JWKSPublisher.get_jwks() do
      {:ok, jwks} ->
        Logger.debug("JWKS endpoint accessed, returning #{length(jwks["keys"])} keys")

        conn
        |> put_resp_header("cache-control", "public, max-age=600, must-revalidate")
        |> put_resp_header("content-type", "application/json; charset=utf-8")
        |> json(jwks)

      {:error, reason} ->
        Logger.error("JWKS endpoint failed: #{inspect(reason)}")

        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "jwks_unavailable", message: "Failed to load public keys"})
    end
  end
end
