defmodule JwsDemo.Partners.Client do
  @moduledoc """
  Client for making signed outbound requests to partner APIs.

  This module demonstrates the client-side of JWS non-repudiation:
  - Sign outbound requests with our private key
  - Send JWS-signed payloads to partner APIs
  - Partners verify our signature to prove authorization

  ## Purpose

  While most of this demo focuses on *receiving* signed requests from partners,
  this module shows the flip side: *sending* signed requests to partners.

  This is important for:
  1. **Webhooks**: Sending signed notifications to partners
  2. **API Calls**: Authorizing actions on partner systems
  3. **Bidirectional Non-Repudiation**: Both parties sign their requests

  ## Example Flow

  ```
  1. We want to notify a partner about a transaction
  2. Create payload with transaction details
  3. Sign payload with our private key
  4. Send JWS to partner's webhook URL
  5. Partner verifies our signature using our public key (from our JWKS endpoint)
  6. Partner processes the verified notification
  ```

  ## Security Considerations

  - Use our private key (kept secret)
  - Partners fetch our public key from /.well-known/jwks.json
  - Include timestamps (iat, exp) for replay protection
  - Include unique ID (jti) for idempotency
  - Partners verify signature before processing

  ## Related Modules

  - `JwsDemo.JWS.Signer` - Signs the payload
  - `JwsDemo.JWS.JWKSPublisher` - Publishes our public keys
  - `JwsDemoWeb.VerifyJWSPlug` - Receives signed requests (server-side)

  """

  require Logger
  alias JwsDemo.JWS.Signer

  @doc """
  Sends a signed request to a partner's API endpoint.

  Creates a JWS-signed payload and sends it via HTTP POST.

  ## Parameters

  - `url` - Partner's API endpoint URL
  - `payload` - Map of data to send (will be signed)
  - `private_key` - Our private key (JOSE.JWK.t())
  - `opts` - Options:
    - `:kid` - Key ID to include in header (required)
    - `:format` - `:compact` or `:flattened` (default: `:flattened`)
    - `:headers` - Additional HTTP headers (default: [])
    - `:timeout` - Request timeout in ms (default: 10000)

  ## Returns

  - `{:ok, response}` - Successful response with status and body
  - `{:error, reason}` - Request failed

  ## Example

      iex> payload = %{
      ...>   "event" => "payment.completed",
      ...>   "transaction_id" => "txn_123",
      ...>   "amount" => 50_000,
      ...>   "currency" => "EUR"
      ...> }
      iex> {:ok, response} = Client.send_signed_request(
      ...>   "https://partner.example.com/webhooks",
      ...>   payload,
      ...>   private_key,
      ...>   kid: "demo-2025-01"
      ...> )
      iex> response.status
      200

  ## Non-Repudiation Proof

  When we send a signed request:
  1. Partner receives JWS with our signature
  2. Partner verifies using our public key (from our JWKS endpoint)
  3. Partner stores signed request in their audit trail
  4. We cannot deny sending this request (cryptographic proof)

  This is the mirror of receiving signed requests from partners.
  """
  @spec send_signed_request(String.t(), map(), JOSE.JWK.t(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def send_signed_request(url, payload, private_key, opts \\ []) do
    kid = Keyword.fetch!(opts, :kid)
    format = Keyword.get(opts, :format, :flattened)
    additional_headers = Keyword.get(opts, :headers, [])
    timeout = Keyword.get(opts, :timeout, 10_000)

    # STEP 1: Sign the payload with our private key
    Logger.debug("Signing outbound request for #{url}")

    signed_payload =
      case format do
        :compact ->
          {:ok, jws} = Signer.sign_compact(payload, private_key, kid: kid)
          jws

        :flattened ->
          {:ok, jws} = Signer.sign_flattened(payload, private_key, kid: kid)
          jws
      end

    # STEP 2: Prepare HTTP request
    headers =
      [
        {"content-type", "application/json"},
        {"user-agent", "JwsDemo/1.0"}
      ] ++ additional_headers

    body =
      case format do
        :compact ->
          # Compact format: send as "jws" field
          Jason.encode!(%{"jws" => signed_payload})

        :flattened ->
          # Flattened JSON: send directly
          Jason.encode!(signed_payload)
      end

    Logger.info("Sending signed request to #{url} (format: #{format}, kid: #{kid})")

    # STEP 3: Send HTTP POST request
    case Req.post(url,
           headers: headers,
           body: body,
           receive_timeout: timeout,
           retry: false
         ) do
      {:ok, %Req.Response{status: status, body: response_body}} ->
        Logger.info("Signed request successful: status=#{status}")

        {:ok,
         %{
           status: status,
           body: response_body,
           format: format,
           kid: kid
         }}

      {:error, reason} ->
        Logger.error("Signed request failed: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @doc """
  Sends a signed webhook notification to a partner.

  Convenience wrapper around `send_signed_request/4` specifically for webhooks.

  ## Parameters

  - `webhook_url` - Partner's webhook endpoint
  - `event_type` - Type of event (e.g., "payment.completed")
  - `event_data` - Event-specific data
  - `private_key` - Our private key
  - `opts` - Options (same as send_signed_request/4)

  ## Example

      iex> Client.send_webhook(
      ...>   "https://partner.example.com/webhooks",
      ...>   "payment.completed",
      ...>   %{"transaction_id" => "txn_123", "amount" => 50_000},
      ...>   private_key,
      ...>   kid: "demo-2025-01"
      ...> )
      {:ok, %{status: 200, body: %{"received" => true}}}

  ## Webhook Payload Structure

  The webhook payload includes:
  - `event` - Event type
  - `timestamp` - Event timestamp (ISO8601)
  - `data` - Event-specific data

  Plus standard JWS claims (iat, exp, jti) added by Signer.
  """
  @spec send_webhook(String.t(), String.t(), map(), JOSE.JWK.t(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def send_webhook(webhook_url, event_type, event_data, private_key, opts \\ []) do
    payload = %{
      "event" => event_type,
      "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "data" => event_data
    }

    Logger.info("Sending webhook: event=#{event_type}, url=#{webhook_url}")
    send_signed_request(webhook_url, payload, private_key, opts)
  end

  @doc """
  Loads our private key from disk for signing outbound requests.

  In production, this would load from secure key storage (HSM, KMS, etc.).
  For this demo, we load from the filesystem.

  ## Parameters

  - `key_path` - Path to private key PEM file (default: priv/keys/demo_private_key.pem)

  ## Returns

  - `{:ok, jwk}` - Loaded private key as JOSE.JWK
  - `{:error, reason}` - Failed to load key

  ## Security Note

  In production:
  - Store private keys in HSM or KMS
  - Use key rotation (every 90 days)
  - Restrict access with IAM policies
  - Never commit private keys to version control
  """
  @spec load_private_key(String.t()) :: {:ok, JOSE.JWK.t()} | {:error, term()}
  def load_private_key(key_path \\ "priv/keys/demo_private_key.pem") do
    case File.read(key_path) do
      {:ok, pem_content} ->
        jwk = JOSE.JWK.from_pem(pem_content)
        {:ok, jwk}

      {:error, reason} ->
        {:error, {:key_load_failed, reason}}
    end
  end
end
