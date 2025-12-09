defmodule JwsDemoWeb.PartnerWebhookController do
  @moduledoc """
  Mock partner webhook endpoint for testing outbound signed requests.

  This controller simulates a partner's API that receives our signed webhooks.
  It demonstrates the partner's perspective: verifying JWS signatures from us.

  ## Purpose

  This is a **testing/demonstration endpoint** that shows:
  - How partners verify our signatures
  - How partners validate webhook payloads
  - The complete bidirectional non-repudiation flow

  ## Flow

  ```
  1. We send signed webhook to partner
  2. Partner receives JWS payload
  3. Partner fetches our public key (from our JWKS endpoint)
  4. Partner verifies our signature
  5. Partner processes verified webhook
  6. Partner stores in their audit trail
  ```

  ## Testing Only

  In production, this endpoint wouldn't exist in our codebase.
  Partners would implement their own verification logic.

  This exists purely for educational purposes and testing.

  ## Related

  - `JwsDemo.Partners.Client` - Sends signed requests (our side)
  - `JwsDemoWeb.VerifyJWSPlug` - Verifies incoming requests (our side)
  - `JwsDemoWeb.JWKSController` - Publishes our public keys

  """

  use JwsDemoWeb, :controller
  require Logger

  alias JwsDemo.JWS.Verifier

  @doc """
  Receives and verifies a signed webhook from us.

  This simulates what a partner would do when receiving our signed webhooks.

  ## Request Format

  **Flattened JSON:**
  ```json
  {
    "payload": "eyJ...",
    "protected": "eyJ...",
    "signature": "..."
  }
  ```

  **Compact format:**
  ```json
  {
    "jws": "eyJ...eyJ...signature"
  }
  ```

  ## Response

  **Success (200):**
  ```json
  {
    "status": "verified",
    "event": "payment.completed",
    "data": {...},
    "verified_at": "2025-12-09T..."
  }
  ```

  **Failure (401):**
  ```json
  {
    "error": "signature_verification_failed",
    "message": "..."
  }
  ```

  """
  def receive_webhook(conn, params) do
    # STEP 1: Extract JWS from request body
    case extract_jws(params) do
      {:ok, jws} ->
        # STEP 2: Fetch our public key (simulating partner fetching from our JWKS)
        # In production, partner would HTTP GET from our /.well-known/jwks.json
        case get_our_public_key() do
          {:ok, public_key} ->
            # STEP 3: Verify signature
            case Verifier.verify(jws, public_key) do
              {:ok, verified_payload} ->
                Logger.info(
                  "Partner verified our webhook: event=#{verified_payload["event"]}"
                )

                handle_verified_webhook(conn, verified_payload)

              {:error, reason} ->
                Logger.warning("Partner rejected our webhook: #{inspect(reason)}")
                handle_verification_error(conn, reason)
            end

          {:error, reason} ->
            Logger.error("Partner failed to fetch our public key: #{inspect(reason)}")

            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "key_fetch_failed", message: "Could not fetch signing key"})
        end

      {:error, reason} ->
        Logger.warning("Partner received invalid JWS: #{inspect(reason)}")

        conn
        |> put_status(:bad_request)
        |> json(%{error: "invalid_jws", message: "Invalid JWS format"})
    end
  end

  # Private functions

  # Extract JWS from request parameters
  defp extract_jws(%{"payload" => _, "protected" => _, "signature" => _} = jws) do
    # Flattened JSON format
    {:ok, jws}
  end

  defp extract_jws(%{"jws" => compact_jws}) when is_binary(compact_jws) do
    # Compact format
    {:ok, compact_jws}
  end

  defp extract_jws(_params) do
    {:error, :invalid_format}
  end

  # Get our public key (simulating partner fetching from our JWKS endpoint)
  # In reality, partner would do: GET https://our-domain.com/.well-known/jwks.json
  defp get_our_public_key do
    # Load our public key from disk (simulates JWKS fetch)
    key_path = Path.join([Application.app_dir(:jws_demo), "priv", "keys", "demo_public_key.pem"])

    case File.read(key_path) do
      {:ok, pem_content} ->
        jwk = JOSE.JWK.from_pem(pem_content)
        {:ok, jwk}

      {:error, reason} ->
        {:error, {:key_not_found, reason}}
    end
  end

  # Handle successfully verified webhook
  defp handle_verified_webhook(conn, verified_payload) do
    # In production, partner would:
    # 1. Store in their audit trail (with original JWS)
    # 2. Process the event
    # 3. Return acknowledgment

    # Extract data - could be in "data" field or directly in payload
    data =
      if Map.has_key?(verified_payload, "data") do
        verified_payload["data"]
      else
        # If no "data" field, return the whole payload minus standard JWS claims
        verified_payload
        |> Map.drop(["iat", "exp", "jti", "event", "timestamp"])
      end

    response = %{
      status: "verified",
      event: Map.get(verified_payload, "event", "unknown"),
      timestamp: verified_payload["timestamp"],
      data: data,
      verified_at: DateTime.utc_now() |> DateTime.to_iso8601(),
      # Include JWS claims for correlation
      jti: verified_payload["jti"],
      iat: verified_payload["iat"],
      exp: verified_payload["exp"]
    }

    conn
    |> put_status(:ok)
    |> json(response)
  end

  # Handle verification errors
  defp handle_verification_error(conn, :invalid_signature) do
    conn
    |> put_status(:unauthorized)
    |> json(%{
      error: "signature_verification_failed",
      message: "JWS signature is invalid or payload was tampered with"
    })
  end

  defp handle_verification_error(conn, :expired) do
    conn
    |> put_status(:unauthorized)
    |> json(%{
      error: "webhook_expired",
      message: "Webhook timestamp is expired"
    })
  end

  defp handle_verification_error(conn, :algorithm_not_allowed) do
    conn
    |> put_status(:unauthorized)
    |> json(%{
      error: "algorithm_not_allowed",
      message: "JWS algorithm not in whitelist"
    })
  end

  defp handle_verification_error(conn, reason) do
    conn
    |> put_status(:unauthorized)
    |> json(%{
      error: "verification_failed",
      message: "Webhook signature verification failed: #{inspect(reason)}"
    })
  end
end
