defmodule JwsDemo.Integration.OutboundRequestTest do
  use JwsDemoWeb.ConnCase, async: false

  alias JwsDemo.Partners.Client

  @moduletag :integration

  setup do
    # Use the demo keypair for integration tests
    # In production, this would be loaded from secure storage
    private_key_path = Path.join([Application.app_dir(:jws_demo), "priv", "keys", "demo_private_key.pem"])
    public_key_path = Path.join([Application.app_dir(:jws_demo), "priv", "keys", "demo_public_key.pem"])

    if File.exists?(private_key_path) and File.exists?(public_key_path) do
      {:ok, private_key} = Client.load_private_key(private_key_path)

      public_pem = File.read!(public_key_path)
      public_key = JOSE.JWK.from_pem(public_pem)

      {:ok, private_key: private_key, public_key: public_key, keys_exist: true}
    else
      # Keys don't exist - skip integration tests
      {:ok, keys_exist: false}
    end
  end

  describe "Outbound signed requests - complete flow" do
    @tag :skip_if_no_keys
    test "send signed webhook to partner (flattened JSON)", %{
      conn: _conn,
      private_key: private_key,
      keys_exist: keys_exist
    } do
      if not keys_exist do
        # Skip test if keys don't exist
        :ok
      else
        IO.puts("\n=== OUTBOUND FLOW: Sending Signed Webhook to Partner ===\n")

        # STEP 1: Prepare webhook payload
        IO.puts("=== STEP 1: Prepare webhook payload ===")

        payload = %{
          "event" => "payment.completed",
          "transaction_id" => "txn_outbound_001",
          "amount" => 75_000,
          "currency" => "GBP",
          "merchant_id" => "merch_xyz"
        }

        IO.puts("✓ Webhook payload created")
        IO.puts("  - Event: #{payload["event"]}")
        IO.puts("  - Transaction: #{payload["transaction_id"]}")
        IO.puts("  - Amount: #{payload["amount"]} #{payload["currency"]}")

        # STEP 2: Sign with our private key
        IO.puts("\n=== STEP 2: Sign webhook with our private key ===")

        mock_partner_url = "http://localhost:#{Application.get_env(:jws_demo, JwsDemoWeb.Endpoint)[:http][:port]}/mock/partner/webhooks"

        {:ok, response} =
          Client.send_signed_request(
            mock_partner_url,
            payload,
            private_key,
            kid: "demo-2025-01",
            format: :flattened
          )

        IO.puts("✓ Webhook signed and sent")
        IO.puts("  - Format: flattened JSON")
        IO.puts("  - Key ID: demo-2025-01")
        IO.puts("  - URL: #{mock_partner_url}")

        # STEP 3: Partner receives and verifies
        IO.puts("\n=== STEP 3: Partner receives and verifies signature ===")

        assert response.status == 200
        assert response.body["status"] == "verified"

        IO.puts("✓ Partner verified our signature successfully")
        IO.puts("  - Status: #{response.body["status"]}")
        IO.puts("  - Event: #{response.body["event"]}")
        IO.puts("  - Verified at: #{response.body["verified_at"]}")

        # STEP 4: Verify payload integrity
        IO.puts("\n=== STEP 4: Verify payload integrity ===")

        assert response.body["event"] == "payment.completed"
        assert response.body["data"]["transaction_id"] == "txn_outbound_001"
        assert response.body["data"]["amount"] == 75_000

        IO.puts("✓ Payload integrity verified")
        IO.puts("  - Transaction ID matches: #{response.body["data"]["transaction_id"]}")
        IO.puts("  - Amount matches: #{response.body["data"]["amount"]}")

        # STEP 5: Verify JWS claims
        IO.puts("\n=== STEP 5: Verify JWS claims (security) ===")

        assert is_binary(response.body["jti"])
        assert is_integer(response.body["iat"])
        assert is_integer(response.body["exp"])

        IO.puts("✓ JWS security claims present")
        IO.puts("  - jti (unique ID): #{response.body["jti"]}")
        IO.puts("  - iat (issued at): #{response.body["iat"]}")
        IO.puts("  - exp (expires): #{response.body["exp"]}")

        IO.puts("\n=== COMPLETE: Outbound non-repudiation flow verified ===\n")
        IO.puts("What this proves:")
        IO.puts("  1. We signed the webhook with our private key")
        IO.puts("  2. Partner verified using our public key (from JWKS)")
        IO.puts("  3. Payload hasn't been tampered with")
        IO.puts("  4. We cannot deny sending this webhook (non-repudiation)")
        IO.puts("  5. Partner can store this in their audit trail as proof")
        IO.puts("")

        # LESSON: This demonstrates the complete outbound flow:
        # 1. We prepare webhook payload
        # 2. We sign with our private key (Client.send_signed_request)
        # 3. Partner receives JWS over HTTPS
        # 4. Partner fetches our public key from /.well-known/jwks.json
        # 5. Partner verifies signature (PartnerWebhookController)
        # 6. Partner processes verified webhook
        # 7. Partner stores in audit trail for non-repudiation
        #
        # This is the mirror of the inbound flow demonstrated in authorization_flow_test.exs
      end
    end

    @tag :skip_if_no_keys
    test "send signed webhook to partner (compact format)", %{
      private_key: private_key,
      keys_exist: keys_exist
    } do
      if not keys_exist do
        :ok
      else
        IO.puts("\n=== OUTBOUND FLOW: Compact Format ===\n")

        # Prepare webhook
        payload = %{
          "event" => "subscription.renewed",
          "subscription_id" => "sub_compact_001",
          "expires_at" => "2026-12-09T00:00:00Z"
        }

        mock_partner_url = "http://localhost:#{Application.get_env(:jws_demo, JwsDemoWeb.Endpoint)[:http][:port]}/mock/partner/webhooks"

        # Send with compact format
        {:ok, response} =
          Client.send_signed_request(
            mock_partner_url,
            payload,
            private_key,
            kid: "demo-2025-01",
            format: :compact
          )

        IO.puts("✓ Compact format webhook sent and verified")
        IO.puts("  - Format: compact (header.payload.signature)")
        IO.puts("  - Partner verified: #{response.body["status"]}")
        IO.puts("  - Event: #{response.body["event"]}")

        assert response.status == 200
        assert response.body["status"] == "verified"
        assert response.body["event"] == "subscription.renewed"

        IO.puts("\n=== COMPLETE: Compact format demonstration ===\n")

        # LESSON: Compact format advantages:
        # - Smaller size (single string)
        # - Can be passed in HTTP headers
        # - Standard format (RFC 7515)
        #
        # Flattened JSON advantages:
        # - More readable
        # - Easier to debug
        # - Better for request bodies
      end
    end

    @tag :skip_if_no_keys
    test "partner rejects tampered webhook", %{
      conn: conn,
      private_key: private_key,
      keys_exist: keys_exist
    } do
      if not keys_exist do
        :ok
      else
        IO.puts("\n=== SECURITY: Tampering Detection ===\n")

        # STEP 1: Create valid signed webhook
        payload = %{
          "event" => "payment.completed",
          "amount" => 10_000
        }

        {:ok, jws} = JwsDemo.JWS.Signer.sign_flattened(payload, private_key, kid: "demo-2025-01")

        IO.puts("✓ Original webhook created")
        IO.puts("  - Amount: #{payload["amount"]}")

        # STEP 2: Attacker tampers with payload
        tampered_payload =
          jws["payload"]
          |> Base.url_decode64!(padding: false)
          |> Jason.decode!()
          |> Map.put("amount", 100_000)  # Change 10K to 100K!
          |> Jason.encode!()
          |> Base.url_encode64(padding: false)

        tampered_jws = %{jws | "payload" => tampered_payload}

        IO.puts("⚠ Attacker tampered with payload")
        IO.puts("  - Changed amount to: 100,000")

        # STEP 3: Partner receives tampered webhook
        conn =
          conn
          |> put_req_header("content-type", "application/json")
          |> post("/mock/partner/webhooks", tampered_jws)

        # VERIFY: Partner rejects tampered webhook
        assert conn.status == 401
        response = json_response(conn, 401)
        assert response["error"] == "signature_verification_failed"

        IO.puts("✓ Partner rejected tampered webhook")
        IO.puts("  - Status: #{conn.status}")
        IO.puts("  - Error: #{response["error"]}")

        IO.puts("\n=== SECURITY VALIDATED: Tampering prevented ===\n")

        # LESSON: JWS signatures prevent tampering:
        # 1. Attacker intercepts webhook
        # 2. Attacker modifies payload (e.g., changes amount)
        # 3. Signature no longer matches modified payload
        # 4. Partner verification fails
        # 5. Partner rejects webhook
        # 6. Attack prevented by cryptography
      end
    end

    @tag :skip_if_no_keys
    test "webhook convenience method", %{
      private_key: private_key,
      keys_exist: keys_exist
    } do
      if not keys_exist do
        :ok
      else
        # Test the send_webhook convenience method
        webhook_url = "http://localhost:#{Application.get_env(:jws_demo, JwsDemoWeb.Endpoint)[:http][:port]}/mock/partner/webhooks"

        event_data = %{
          "invoice_id" => "inv_webhook_001",
          "amount" => 50_000,
          "paid_at" => "2025-12-09T10:00:00Z"
        }

        {:ok, response} =
          Client.send_webhook(
            webhook_url,
            "invoice.paid",
            event_data,
            private_key,
            kid: "demo-2025-01"
          )

        assert response.status == 200
        assert response.body["status"] == "verified"
        assert response.body["event"] == "invoice.paid"
        assert response.body["data"]["invoice_id"] == "inv_webhook_001"

        # LESSON: send_webhook is a convenience wrapper that:
        # - Structures webhook payload (event, timestamp, data)
        # - Signs with our private key
        # - Sends to partner's webhook URL
        # - Returns verification result
      end
    end
  end

  describe "Bidirectional non-repudiation" do
    @tag :skip_if_no_keys
    test "demonstrates both directions of signed requests", %{
      private_key: private_key,
      keys_exist: keys_exist
    } do
      if not keys_exist do
        :ok
      else
        IO.puts("\n=== BIDIRECTIONAL NON-REPUDIATION ===\n")

        IO.puts("Direction 1: Partner → Us (Inbound)")
        IO.puts("  - Partner signs authorization request")
        IO.puts("  - We verify partner's signature")
        IO.puts("  - We store in audit trail")
        IO.puts("  - Partner cannot deny sending request")
        IO.puts("  (See: test/jws_demo/integration/authorization_flow_test.exs)")

        IO.puts("\nDirection 2: Us → Partner (Outbound)")
        IO.puts("  - We sign webhook notification")
        IO.puts("  - Partner verifies our signature")
        IO.puts("  - Partner stores in their audit trail")
        IO.puts("  - We cannot deny sending webhook")
        IO.puts("  (This test)")

        # Demonstrate outbound direction
        webhook_url = "http://localhost:#{Application.get_env(:jws_demo, JwsDemoWeb.Endpoint)[:http][:port]}/mock/partner/webhooks"

        {:ok, response} =
          Client.send_webhook(
            webhook_url,
            "test.bidirectional",
            %{"test" => "data"},
            private_key,
            kid: "demo-2025-01"
          )

        assert response.status == 200
        assert response.body["status"] == "verified"

        IO.puts("\n✓ Bidirectional non-repudiation demonstrated")
        IO.puts("\nKey Insight:")
        IO.puts("  Both parties sign their requests → Both parties have non-repudiation")
        IO.puts("  This creates a complete audit trail for dispute resolution")
        IO.puts("")

        # LESSON: Bidirectional non-repudiation means:
        # - Both parties sign their requests
        # - Both parties verify incoming signatures
        # - Both parties store signed requests in audit trails
        # - Neither party can deny their actions
        # - Complete audit trail for regulatory compliance
      end
    end

    @tag :skip_if_no_keys
    test "creates audit log for outbound request", %{
      private_key: private_key,
      keys_exist: keys_exist
    } do
      if not keys_exist do
        :ok
      else
        IO.puts("\n=== OUTBOUND AUDIT TRAIL ===\n")

        webhook_url = "http://localhost:#{Application.get_env(:jws_demo, JwsDemoWeb.Endpoint)[:http][:port]}/mock/partner/webhooks"

        # BEFORE: Count existing outbound audit logs
        import Ecto.Query
        before_count = JwsDemo.Repo.one(
          from a in JwsDemo.AuditLogs.AuditLog,
          where: a.direction == "outbound",
          select: count(a.id)
        )

        IO.puts("✓ Outbound audit logs before: #{before_count}")

        # SEND: Webhook with audit enabled
        {:ok, response} =
          JwsDemo.Partners.Client.send_webhook(
            webhook_url,
            "payment.completed",
            %{
              "transaction_id" => "txn_audit_outbound_001",
              "amount" => 100_000,
              "currency" => "USD"
            },
            private_key,
            kid: "demo-2025-01",
            audit: true,
            partner_id: "partner_outbound_test"
          )

        assert response.status == 200

        IO.puts("✓ Webhook sent successfully")

        # AFTER: Verify audit log was created
        after_count = JwsDemo.Repo.one(
          from a in JwsDemo.AuditLogs.AuditLog,
          where: a.direction == "outbound",
          select: count(a.id)
        )

        assert after_count == before_count + 1

        IO.puts("✓ Outbound audit logs after: #{after_count}")

        # VERIFY: Audit log contains correct data
        # The transaction_id is now extracted and stored as instruction_id
        audit_log = JwsDemo.Repo.one(
          from a in JwsDemo.AuditLogs.AuditLog,
          where: a.direction == "outbound" and a.instruction_id == "txn_audit_outbound_001",
          order_by: [desc: a.inserted_at],
          limit: 1
        )

        assert audit_log != nil
        assert audit_log.direction == "outbound"
        assert audit_log.uri == webhook_url
        assert audit_log.response_status == 200
        assert is_map(audit_log.response_body)
        assert audit_log.response_body["status"] == "verified"

        IO.puts("✓ Audit log created with:")
        IO.puts("  - Direction: #{audit_log.direction}")
        IO.puts("  - URI: #{audit_log.uri}")
        IO.puts("  - Response Status: #{audit_log.response_status}")
        IO.puts("  - Partner Response: #{audit_log.response_body["status"]}")

        IO.puts("\n=== COMPLETE: Outbound audit trail verified ===\n")

        # LESSON: Outbound audit logs prove:
        # - We sent this specific webhook (original JWS stored)
        # - Partner received and verified it (response status + body)
        # - Complete bidirectional audit trail
        # - Both parties have cryptographic proof
      end
    end
  end
end
