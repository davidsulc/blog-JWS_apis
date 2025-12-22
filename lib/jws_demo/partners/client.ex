defmodule JwsDemo.Partners.Client do
  @moduledoc """
  Client for making signed outbound requests to partner APIs with bidirectional verification.

  This module demonstrates the complete bidirectional JWS non-repudiation pattern:
  - Sign outbound requests with our private key
  - Send JWS-signed payloads to partner APIs
  - Partners verify our signature to prove authorization
  - **Verify partner's signed response** for complete non-repudiation
  - Store both signatures in audit trail

  ## Purpose

  While most of this demo focuses on *receiving* signed requests from partners,
  this module shows the flip side: *sending* signed requests to partners AND
  verifying their signed responses.

  This is important for:
  1. **Webhooks**: Sending signed notifications to partners
  2. **API Calls**: Authorizing actions on partner systems
  3. **Bidirectional Non-Repudiation**: Both parties sign their messages
  4. **Complete Audit Trail**: Cryptographic proof of both request and response

  ## Complete Bidirectional Flow

  ```
  1. We sign our request with our private key
  2. Send JWS to partner's webhook URL
  3. Partner verifies our signature using our public key (from our JWKS endpoint)
  4. Partner processes the request and signs their response with their private key
  5. We verify partner's response signature using their public key (from their JWKS)
  6. We store both signatures in our audit trail

  Result: Neither party can deny sending their message or receiving the other's message.
  ```

  ## Security Considerations

  - Use our private key (kept secret)
  - Partners fetch our public key from /.well-known/jwks.json
  - We fetch partner's public key from their JWKS endpoint (cached)
  - Include timestamps (iat, exp) for replay protection
  - Include unique ID (jti) for idempotency
  - Both signatures verified before processing
  - Complete audit trail stored for dispute resolution

  ## Related Modules

  - `JwsDemo.JWS.Signer` - Signs our outbound payloads
  - `JwsDemo.JWS.Verifier` - Verifies partner's response signatures
  - `JwsDemo.JWS.JWKSCache` - Fetches and caches partner public keys
  - `JwsDemo.JWS.JWKSPublisher` - Publishes our public keys
  - `JwsDemoWeb.VerifyJWSPlug` - Receives signed requests (server-side)

  """

  require Logger
  alias JwsDemo.JWS.Signer
  alias JwsDemo.JWS.Audit
  alias JwsDemo.JWS.Verifier
  alias JwsDemo.JWS.JWKSCache

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
    - `:audit` - Enable audit logging (default: false)
    - `:partner_id` - Partner identifier for audit trail (required if audit: true)

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

  ## Bidirectional Non-Repudiation

  When we send a signed request:
  1. Partner receives JWS with our signature
  2. Partner verifies using our public key (from our JWKS endpoint)
  3. Partner signs their response with their private key
  4. We verify partner's response using their public key (from their JWKS)
  5. We store both signatures in our audit trail
  6. Neither party can deny the interaction (cryptographic proof)

  This is the complete bidirectional pattern - both request and response are signed
  and verified, providing cryptographic proof for both parties.
  """
  @spec send_signed_request(String.t(), map(), JOSE.JWK.t(), keyword()) ::
          {:ok, map()} | {:error, term()}
  def send_signed_request(url, payload, private_key, opts \\ []) do
    kid = Keyword.fetch!(opts, :kid)
    format = Keyword.get(opts, :format, :flattened)
    additional_headers = Keyword.get(opts, :headers, [])
    timeout = Keyword.get(opts, :timeout, 10_000)
    audit_enabled = Keyword.get(opts, :audit, false)
    partner_id = Keyword.get(opts, :partner_id)

    # STEP 1: Sign the payload with our private key
    Logger.debug("Signing outbound request for #{url}")

    {signed_payload, signed_jws_string} =
      case format do
        :compact ->
          {:ok, jws} = Signer.sign_compact(payload, private_key, kid: kid)
          {jws, jws}

        :flattened ->
          {:ok, jws} = Signer.sign_flattened(payload, private_key, kid: kid)
          # Convert to compact for audit storage
          jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"
          {jws, jws_string}
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

        # STEP 4: Verify partner's signed response (if present)
        verified_response_result =
          if partner_id do
            verify_partner_response(response_body, partner_id)
          else
            {:ok, nil}
          end

        # STEP 5: Create audit log if enabled
        if audit_enabled and partner_id do
          create_outbound_audit_log(
            payload,
            private_key,
            signed_jws_string,
            partner_id,
            url,
            status,
            response_body,
            verified_response_result
          )
        end

        {:ok,
         %{
           status: status,
           body: response_body,
           verified_response: verified_response_result,
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

  # Private functions

  # Verify partner's signed response
  defp verify_partner_response(response_body, partner_id) when is_map(response_body) do
    # Check if response contains JWS signature
    case response_body do
      %{"jws" => jws_string} when is_binary(jws_string) ->
        verify_partner_jws(jws_string, partner_id)

      %{"protected" => _, "payload" => _, "signature" => _} = jws_flattened ->
        verify_partner_jws(jws_flattened, partner_id)

      _ ->
        Logger.warning("Partner response not signed (no JWS found): partner_id=#{partner_id}")
        {:error, :response_not_signed}
    end
  end

  defp verify_partner_response(_response_body, _partner_id) do
    {:error, :invalid_response_format}
  end

  defp verify_partner_jws(jws, partner_id) do
    # Extract kid from JWS header
    with {:ok, header} <- extract_jws_header(jws),
         {:ok, kid} <- Map.fetch(header, "kid"),
         {:ok, partner_jwk} <- JWKSCache.get_key(partner_id, kid),
         {:ok, verified_payload} <- Verifier.verify(jws, partner_jwk) do
      Logger.info("Partner response signature verified: partner_id=#{partner_id}, kid=#{kid}")
      {:ok, %{verified_payload: verified_payload, kid: kid}}
    else
      {:error, reason} ->
        Logger.error("Partner response signature verification failed: #{inspect(reason)}")
        {:error, {:verification_failed, reason}}

      :error ->
        Logger.error("Partner response missing kid in JWS header")
        {:error, :missing_kid}
    end
  end

  defp extract_jws_header(jws) when is_binary(jws) do
    case String.split(jws, ".") do
      [header_b64, _, _] ->
        with {:ok, header_json} <- Base.url_decode64(header_b64, padding: false),
             {:ok, header} <- Jason.decode(header_json) do
          {:ok, header}
        end

      _ ->
        {:error, :invalid_jws_format}
    end
  end

  defp extract_jws_header(%{"protected" => protected_b64}) when is_binary(protected_b64) do
    with {:ok, header_json} <- Base.url_decode64(protected_b64, padding: false),
         {:ok, header} <- Jason.decode(header_json) do
      {:ok, header}
    end
  end

  defp extract_jws_header(_), do: {:error, :invalid_jws_format}

  # Create audit log for outbound request
  defp create_outbound_audit_log(
         _payload,
         private_key,
         jws_signature,
         partner_id,
         url,
         status,
         response_body,
         verified_response_result
       ) do
    # Get the verified payload (add automatic claims that were added during signing)
    # We need to reconstruct this from the JWS to get iat, exp, jti
    [_protected, payload_b64, _signature] = String.split(jws_signature, ".")
    verified_payload = payload_b64 |> Base.url_decode64!(padding: false) |> Jason.decode!()

    # Extract instruction_id from payload
    # For webhooks: data.transaction_id or data.subscription_id or data.invoice_id
    # For direct requests: instruction_id at top level
    instruction_id = extract_instruction_id(verified_payload)

    # Add instruction_id to verified_payload for audit logging
    verified_payload_with_id = Map.put(verified_payload, "instruction_id", instruction_id)

    # Include verified response data if signature verification succeeded
    verified_response_metadata =
      case verified_response_result do
        {:ok, %{verified_payload: verified_resp, kid: resp_kid}} ->
          %{
            response_signature_verified: true,
            response_verified_payload: verified_resp,
            response_verification_kid: resp_kid
          }

        {:ok, nil} ->
          # No partner_id provided, skip verification
          %{}

        {:error, reason} ->
          %{
            response_signature_verified: false,
            response_verification_error: inspect(reason)
          }
      end

    metadata =
      %{
        partner_id: partner_id,
        jws_signature: jws_signature,
        verification_algorithm: "ES256",
        verification_kid: verified_payload["kid"],
        direction: "outbound",
        uri: url,
        response_status: status,
        response_body: if(is_map(response_body), do: response_body, else: nil)
      }
      |> Map.merge(verified_response_metadata)

    case Audit.log_authorization(verified_payload_with_id, private_key, metadata) do
      {:ok, audit_log} ->
        Logger.info(
          "Outbound audit log created: id=#{audit_log.id}, uri=#{audit_log.uri}, status=#{audit_log.response_status}"
        )

        :ok

      {:error, changeset} ->
        Logger.error("Failed to create outbound audit log: #{inspect(changeset.errors)}")
        :error
    end
  end

  # Extract instruction ID from various payload structures
  defp extract_instruction_id(%{"instruction_id" => id}) when is_binary(id), do: id

  defp extract_instruction_id(%{"data" => %{"transaction_id" => id}}) when is_binary(id), do: id
  defp extract_instruction_id(%{"data" => %{"subscription_id" => id}}) when is_binary(id), do: id
  defp extract_instruction_id(%{"data" => %{"invoice_id" => id}}) when is_binary(id), do: id

  defp extract_instruction_id(%{"jti" => jti}) when is_binary(jti), do: "jti_#{jti}"

  defp extract_instruction_id(_), do: "unknown_#{UUID.uuid4()}"
end
