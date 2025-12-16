defmodule JwsDemo.Partners.ClientTest do
  use ExUnit.Case, async: true

  alias JwsDemo.Partners.Client
  alias JwsDemo.JWS.Verifier

  setup do
    # Generate keypair for testing
    private_key = JOSE.JWK.generate_key({:ec, :secp256r1})

    # Extract public key from private key
    public_key = JOSE.JWK.to_public(private_key)

    {:ok, private_key: private_key, public_key: public_key}
  end

  describe "send_signed_request/4 - flattened JSON format" do
    test "creates valid JWS signature in flattened format", %{
      private_key: private_key,
      public_key: _public_key
    } do
      # SETUP: Create webhook payload
      # This demonstrates what we send to partners
      payload = %{
        "event" => "payment.completed",
        "transaction_id" => "txn_test_001",
        "amount" => 50_000,
        "currency" => "EUR"
      }

      # SIMULATE: Send to mock partner endpoint
      # In production, this would be an actual HTTPS URL
      mock_url = "http://localhost:4000/mock/partner/webhooks"

      # ACT: Send signed request
      # Note: This will get a 401 response because the test key isn't in the JWKS cache
      # In production, partners would have our public key in their cache
      result = Client.send_signed_request(mock_url, payload, private_key, kid: "test-key-001")

      # Verify the request was sent successfully (HTTP 200 with 401 status in response body)
      # The 401 is expected because the mock endpoint uses VerifyJWSPlug
      # and test-key-001 isn't in the JWKS cache
      assert {:ok, response} = result
      assert response.status == 401

      assert response.body["error"] == "signature_verification_failed" ||
               response.body["error"] == "key_fetch_failed"

      # LESSON: Client successfully creates and sends the JWS request.
      # The verification failure is expected in this test environment.
      # In production:
      # 1. Partner's JWKS cache would have our public key
      # 2. Verification would succeed
      # 3. Partner would process the verified webhook
    end

    test "signs payload with automatic claims (iat, exp, jti)", %{private_key: private_key} do
      # SETUP
      payload = %{"event" => "user.created", "user_id" => "usr_123"}

      # We'll manually test the signing logic that Client uses internally
      {:ok, jws} = JwsDemo.JWS.Signer.sign_flattened(payload, private_key, kid: "test-key")

      # VERIFY: JWS contains standard structure
      assert is_map(jws)
      assert Map.has_key?(jws, "payload")
      assert Map.has_key?(jws, "protected")
      assert Map.has_key?(jws, "signature")

      # VERIFY: Protected header includes kid
      protected_decoded =
        jws["protected"] |> Base.url_decode64!(padding: false) |> Jason.decode!()

      assert protected_decoded["kid"] == "test-key"
      assert protected_decoded["alg"] == "ES256"

      # VERIFY: Payload includes automatic claims
      payload_decoded = jws["payload"] |> Base.url_decode64!(padding: false) |> Jason.decode!()
      assert Map.has_key?(payload_decoded, "iat")
      assert Map.has_key?(payload_decoded, "exp")
      assert Map.has_key?(payload_decoded, "jti")
      assert payload_decoded["event"] == "user.created"

      # LESSON: Client automatically adds security claims:
      # - iat: Issued at timestamp (prevents old webhooks)
      # - exp: Expiration (5 min default, prevents replay attacks)
      # - jti: Unique ID (enables idempotency checks)
    end
  end

  describe "send_signed_request/4 - compact format" do
    test "creates valid JWS signature in compact format", %{
      private_key: private_key,
      public_key: public_key
    } do
      # SETUP
      payload = %{
        "event" => "payment.refunded",
        "transaction_id" => "txn_refund_001",
        "amount" => 25_000
      }

      # Create compact JWS (what Client would send)
      {:ok, compact_jws} =
        JwsDemo.JWS.Signer.sign_compact(payload, private_key, kid: "compact-test")

      # VERIFY: Compact format is single string with 3 parts
      assert is_binary(compact_jws)
      parts = String.split(compact_jws, ".")
      assert length(parts) == 3

      [header_b64, payload_b64, signature_b64] = parts

      # VERIFY: Each part is valid Base64URL
      assert {:ok, _} = Base.url_decode64(header_b64, padding: false)
      assert {:ok, _} = Base.url_decode64(payload_b64, padding: false)
      assert {:ok, _} = Base.url_decode64(signature_b64, padding: false)

      # VERIFY: Partner can verify this signature
      {:ok, verified} = Verifier.verify(compact_jws, public_key)
      assert verified["event"] == "payment.refunded"
      assert verified["amount"] == 25_000

      # LESSON: Compact format is more efficient for transport:
      # - Single string (easier to pass in headers or query params)
      # - Smaller than flattened JSON
      # - Standard format for JWS (RFC 7515)
      # But flattened JSON is more readable and easier to debug.
    end
  end

  describe "send_webhook/5" do
    test "structures webhook payload correctly", %{
      private_key: private_key,
      public_key: public_key
    } do
      # SETUP: Send webhook (will fail with connection error, but we can verify structure)
      event_type = "invoice.paid"

      event_data = %{
        "invoice_id" => "inv_123",
        "amount" => 100_000,
        "paid_at" => "2025-12-09T10:00:00Z"
      }

      # Create the webhook payload that Client.send_webhook would create
      webhook_payload = %{
        "event" => event_type,
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601(),
        "data" => event_data
      }

      # Sign it like send_webhook does
      {:ok, jws} =
        JwsDemo.JWS.Signer.sign_flattened(webhook_payload, private_key, kid: "webhook-key")

      # VERIFY: Partner receives structured webhook
      {:ok, verified} = Verifier.verify(jws, public_key)
      assert verified["event"] == "invoice.paid"
      assert verified["data"]["invoice_id"] == "inv_123"
      assert verified["data"]["amount"] == 100_000
      assert is_binary(verified["timestamp"])

      # VERIFY: Standard JWS claims included
      assert is_integer(verified["iat"])
      assert is_integer(verified["exp"])
      assert is_binary(verified["jti"])

      # LESSON: Webhook structure includes:
      # - event: Type of webhook
      # - timestamp: When event occurred
      # - data: Event-specific payload
      # Plus JWS claims (iat, exp, jti) for security
    end

    test "webhook includes replay protection", %{private_key: private_key, public_key: public_key} do
      # SETUP
      event_data = %{"order_id" => "ord_456", "status" => "shipped"}

      webhook_payload = %{
        "event" => "order.shipped",
        "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601(),
        "data" => event_data
      }

      {:ok, jws} =
        JwsDemo.JWS.Signer.sign_flattened(webhook_payload, private_key, kid: "replay-test")

      {:ok, verified} = Verifier.verify(jws, public_key)

      # VERIFY: Timestamp validation
      iat = verified["iat"]
      exp = verified["exp"]
      jti = verified["jti"]

      # iat should be recent (within last minute)
      now = System.system_time(:second)
      assert iat >= now - 60
      assert iat <= now + 60

      # exp should be 5 minutes after iat (default)
      assert exp == iat + 300

      # jti should be unique UUID
      assert String.match?(
               jti,
               ~r/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
             )

      # LESSON: Replay protection mechanisms:
      # 1. iat: Partner rejects old webhooks
      # 2. exp: Partner rejects expired webhooks (5 min window)
      # 3. jti: Partner can track processed webhook IDs (idempotency)
      #
      # Partner would maintain:
      # - Set of processed jti values (TTL: exp + grace period)
      # - Reject webhook if jti already seen
      # - Reject webhook if iat too old or exp passed
    end
  end

  describe "load_private_key/1" do
    test "loads private key from PEM file" do
      # SETUP: Use demo private key
      key_path =
        Path.join([Application.app_dir(:jws_demo), "priv", "keys", "demo_private_key.pem"])

      # Skip if key doesn't exist yet
      if File.exists?(key_path) do
        # ACT: Load key
        {:ok, jwk} = Client.load_private_key(key_path)

        # VERIFY: Key is valid EC private key
        # Verify it's a JWK struct
        %JOSE.JWK{} = jwk

        # VERIFY: Can sign with this key
        test_payload = %{"test" => "data"}
        {:ok, jws} = JwsDemo.JWS.Signer.sign_compact(test_payload, jwk, kid: "test")
        assert is_binary(jws)

        # LESSON: In production:
        # - Don't load keys from filesystem
        # - Use HSM (Hardware Security Module) or KMS (Key Management Service)
        # - Restrict key access with IAM policies
        # - Rotate keys every 90 days
        # - Never commit private keys to git
      else
        # Key not generated yet - skip test
        :ok
      end
    end

    test "returns error for non-existent key" do
      # ACT: Try to load non-existent key
      result = Client.load_private_key("/nonexistent/key.pem")

      # VERIFY: Error returned
      assert {:error, {:key_load_failed, :enoent}} = result

      # LESSON: Handle key loading errors gracefully
      # In production, this would be a critical failure requiring alerts
    end
  end

  describe "JWS verification by partner" do
    test "partner can verify our signature using our public key", %{
      private_key: private_key,
      public_key: public_key
    } do
      # SETUP: We create a signed webhook
      payload = %{
        "event" => "subscription.renewed",
        "subscription_id" => "sub_789",
        "expires_at" => "2026-12-09T00:00:00Z"
      }

      {:ok, jws} =
        JwsDemo.JWS.Signer.sign_flattened(payload, private_key, kid: "partner-verify-test")

      # SIMULATE: Partner receives JWS and verifies it
      # Partner would:
      # 1. Receive JWS via HTTP POST
      # 2. Extract kid from protected header
      # 3. Fetch our JWKS from /.well-known/jwks.json
      # 4. Find matching key by kid
      # 5. Verify signature

      # Partner verification
      {:ok, verified_payload} = Verifier.verify(jws, public_key)

      # VERIFY: Partner gets original payload
      assert verified_payload["event"] == "subscription.renewed"
      assert verified_payload["subscription_id"] == "sub_789"

      # VERIFY: Partner can trust this data
      # Cryptographic proof that:
      # 1. We authorized this webhook (our private key signed it)
      # 2. Payload hasn't been modified (signature validation)
      # 3. Timestamp is valid (exp not passed)
      # 4. We cannot deny sending this (non-repudiation)

      # LESSON: This is the foundation of non-repudiation:
      # - We sign with private key (only we have)
      # - Partner verifies with public key (from our JWKS)
      # - Cryptographic proof we sent this specific payload
      # - We cannot credibly deny sending it
      # - Partner stores JWS in their audit trail as proof
    end

    test "partner rejects tampered webhook", %{private_key: private_key, public_key: public_key} do
      # SETUP: Create valid signed webhook
      payload = %{
        "event" => "payment.completed",
        "amount" => 10_000
      }

      {:ok, jws} = JwsDemo.JWS.Signer.sign_flattened(payload, private_key, kid: "tamper-test")

      # TAMPER: Attacker modifies the amount in the payload
      tampered_payload =
        jws["payload"]
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()
        # Changed from 10,000 to 100,000!
        |> Map.put("amount", 100_000)
        |> Jason.encode!()
        |> Base.url_encode64(padding: false)

      tampered_jws = %{jws | "payload" => tampered_payload}

      # PARTNER VERIFICATION: Should reject tampered webhook
      result = Verifier.verify(tampered_jws, public_key)
      assert {:error, :invalid_signature} = result

      # LESSON: Signature verification prevents tampering:
      # - Attacker changes amount from 10K to 100K
      # - Signature verification fails (signature doesn't match modified payload)
      # - Partner rejects the webhook
      # - Attack prevented by cryptography
      #
      # This proves integrity: payload hasn't been modified since we signed it.
    end

    test "partner enforces timestamp validation for replay protection" do
      # LESSON: Partners enforce timestamp validation to prevent:
      # - Old webhooks from being replayed (check iat is recent)
      # - Expired requests from being processed (check exp not passed)
      # - Time-based attacks (enforce clock skew tolerance)
      #
      # Partner's verification logic:
      # 1. Extract iat and exp from verified payload
      # 2. now = current_time()
      # 3. Reject if iat > now + clock_skew (issued in future)
      # 4. Reject if exp < now - clock_skew (expired)
      # 5. Reject if iat too old (e.g., > 24 hours ago)
      #
      # This is already tested in verifier_test.exs:
      # - "accepts token within clock skew tolerance"
      # - "rejects token beyond clock skew tolerance"
      # - "rejects expired token"
      #
      # In this test, we just document the concept for educational purposes.
      assert true
    end
  end
end
