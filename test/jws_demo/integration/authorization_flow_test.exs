defmodule JwsDemo.Integration.AuthorizationFlowTest do
  @moduledoc """
  End-to-end integration tests demonstrating complete authorization flow.

  These tests show the full lifecycle:
  1. Partner signs authorization with JWS
  2. POST request to authorization endpoint
  3. Signature verification via VerifyJWSPlug
  4. Authorization processing
  5. Audit trail storage
  6. Re-verification from audit log
  7. Verification package generation

  This proves the complete non-repudiation system.
  """

  use JwsDemoWeb.ConnCase, async: false

  alias JwsDemo.JWS.{Signer, Audit}
  alias JwsDemo.Repo
  alias JwsDemo.Partners.Partner

  # Note: async: false because we're populating global JWKS cache ETS table

  # Helper to suppress IO output in tests by default
  defp test_puts(msg) do
    if System.get_env("TEST_VERBOSE") == "true" do
      IO.puts(msg)
    end
  end

  setup do
    # Generate test keypair
    jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
    kid = "integration-key-2025"

    # Create test partner
    partner =
      %Partner{}
      |> Partner.changeset(%{
        partner_id: "partner_integration_test_#{:rand.uniform(1_000_000)}",
        name: "Integration Test Partner",
        active: true
      })
      |> Repo.insert!()

    # Manually insert public key into JWKS cache for testing
    now = System.system_time(:second)
    ttl = 900
    cache_key = {partner.partner_id, kid}
    :ets.insert(:jwks_cache, {cache_key, jwk, now, ttl})

    {:ok, jwk: jwk, partner: partner, kid: kid}
  end

  describe "complete authorization flow" do
    test "sign → verify → process → audit → re-verify", %{
      conn: conn,
      jwk: jwk,
      partner: partner,
      kid: kid
    } do
      # STEP 1: Partner creates authorization payload
      payload = %{
        "instruction_id" => "txn_integration_001",
        "amount" => 100_000,
        "currency" => "EUR",
        "merchant_id" => "merchant_xyz",
        "description" => "Purchase Order #12345"
      }

      test_puts("\n=== STEP 1: Partner signs authorization ===")

      # STEP 2: Partner signs with JWS (flattened JSON)
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      test_puts("✓ JWS created with flattened JSON format")
      test_puts("  - Protected header: #{String.slice(jws["protected"], 0, 40)}...")
      test_puts("  - Payload: #{String.slice(jws["payload"], 0, 40)}...")
      test_puts("  - Signature: #{String.slice(jws["signature"], 0, 40)}...")

      # STEP 3: POST to authorization endpoint (VerifyJWSPlug will verify)
      test_puts("\n=== STEP 2: Server verifies signature (via VerifyJWSPlug) ===")

      conn =
        conn
        |> put_req_header("x-partner-id", partner.partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      test_puts("\n=== STEP 3: Process authorization ===")

      # VERIFY: 200 response with approval
      assert response = json_response(conn, 200)
      assert response["status"] == "approved"
      assert response["instruction_id"] == "txn_integration_001"
      assert response["amount"] == 100_000

      test_puts("✓ Signature verified and authorization approved")
      test_puts("  - Status: #{response["status"]}")
      test_puts("  - Instruction ID: #{response["instruction_id"]}")
      test_puts("  - JTI: #{response["jti"]}")
      test_puts("  - Exp: #{response["exp"]}")

      # STEP 4: Verify audit trail was created (automatic via controller)
      test_puts("\n=== STEP 4: Verify audit trail ===")

      audit_log = Repo.get_by(JwsDemo.AuditLogs.AuditLog, instruction_id: "txn_integration_001")
      assert audit_log != nil

      test_puts("✓ Audit log created automatically")
      test_puts("  - Audit ID: #{audit_log.id}")
      test_puts("  - Original JWS stored: #{String.length(audit_log.jws_signature)} bytes")
      test_puts("  - Partner key snapshot stored: ✓")

      # STEP 5: Re-verify from audit log (simulate months later)
      test_puts("\n=== STEP 5: Re-verify from audit trail ===")
      {:ok, reverified} = Audit.re_verify("txn_integration_001")

      assert reverified["amount"] == 100_000
      assert reverified["instruction_id"] == "txn_integration_001"

      test_puts("✓ Re-verification successful (proves non-repudiation)")
      test_puts("  - Amount verified: #{reverified["amount"]}")
      test_puts("  - Instruction ID: #{reverified["instruction_id"]}")

      # STEP 6: Generate verification package
      test_puts("\n=== STEP 6: Generate verification package ===")
      output_dir = System.tmp_dir!() |> Path.join("integration_test_#{:rand.uniform(1_000_000)}")

      assert :ok = Audit.generate_verification_package("txn_integration_001", output_dir)

      # Verify all files exist
      assert File.exists?(Path.join(output_dir, "jws_original.txt"))
      assert File.exists?(Path.join(output_dir, "public_key.pem"))
      assert File.exists?(Path.join(output_dir, "public_key.jwk"))
      assert File.exists?(Path.join(output_dir, "payload_decoded.json"))
      assert File.exists?(Path.join(output_dir, "VERIFICATION.md"))

      test_puts("✓ Verification package generated")
      test_puts("  - Location: #{output_dir}")

      test_puts(
        "  - Files: jws_original.txt, public_key.pem, public_key.jwk, payload_decoded.json, VERIFICATION.md"
      )

      # Cleanup
      File.rm_rf!(output_dir)

      test_puts("\n=== COMPLETE: Full non-repudiation flow verified ===\n")

      # LESSON: This test demonstrates the complete lifecycle of a
      # JWS-signed authorization with non-repudiation guarantees:
      # 1. Partner signs with JWS
      # 2. VerifyJWSPlug verifies signature (automatic via pipeline)
      # 3. Controller processes and creates audit log
      # 4. Audit trail enables re-verification years later
      # 5. Verification package enables independent audit
    end

    test "multiple authorizations are isolated in audit trail", %{
      conn: conn,
      jwk: jwk,
      partner: partner,
      kid: kid
    } do
      # Create two separate authorizations by posting to endpoint
      payloads = [
        %{"instruction_id" => "txn_multi_001", "amount" => 50_000},
        %{"instruction_id" => "txn_multi_002", "amount" => 75_000}
      ]

      responses =
        Enum.map(payloads, fn payload ->
          {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

          conn
          |> recycle()
          |> put_req_header("x-partner-id", partner.partner_id)
          |> put_req_header("content-type", "application/json")
          |> post(~p"/api/v1/authorizations", jws)
          |> json_response(200)
        end)

      # Verify both were approved
      assert length(responses) == 2
      assert Enum.all?(responses, fn r -> r["status"] == "approved" end)

      # Verify we can query each independently
      {:ok, txn1} = Audit.re_verify("txn_multi_001")
      {:ok, txn2} = Audit.re_verify("txn_multi_002")

      assert txn1["amount"] == 50_000
      assert txn2["amount"] == 75_000

      # LESSON: Audit trail maintains separate, independent records
      # for each authorization, enabling granular re-verification.
    end

    test "tampered audit log is detected on re-verification", %{
      conn: conn,
      jwk: jwk,
      partner: partner,
      kid: kid
    } do
      # Create authorization via endpoint (which creates audit log)
      payload = %{"instruction_id" => "txn_tamper_test", "amount" => 10_000}
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      conn
      |> put_req_header("x-partner-id", partner.partner_id)
      |> put_req_header("content-type", "application/json")
      |> post(~p"/api/v1/authorizations", jws)
      |> json_response(200)

      # Get the audit log that was created
      audit_log = Repo.get_by(JwsDemo.AuditLogs.AuditLog, instruction_id: "txn_tamper_test")
      assert audit_log != nil

      # Tamper with the stored JWS (simulate database attack)
      parts = String.split(audit_log.jws_signature, ".")
      tampered_sig = "TAMPERED" <> String.slice(Enum.at(parts, 2), 8, 1000)
      tampered_jws = "#{Enum.at(parts, 0)}.#{Enum.at(parts, 1)}.#{tampered_sig}"

      audit_log
      |> Ecto.Changeset.change(jws_signature: tampered_jws)
      |> Repo.update!()

      # Re-verification should fail
      assert {:error, {:verification_failed, :invalid_signature}} =
               Audit.re_verify("txn_tamper_test")

      # LESSON: Audit trail protects against tampering. Any modification
      # to the stored JWS is immediately detected on re-verification.
    end
  end

  describe "error scenarios" do
    test "expired token is rejected", %{jwk: jwk} do
      # Create token that already expired
      now = System.system_time(:second)

      payload = %{
        "instruction_id" => "txn_expired",
        "amount" => 50_000,
        "iat" => now - 900,
        "exp" => now - 600,
        "jti" => UUID.uuid4()
      }

      payload_json = Jason.encode!(payload, pretty: false)
      protected = %{"alg" => "ES256", "typ" => "JWT", "kid" => "expired-key"}

      {_alg, compact_jws} =
        JOSE.JWS.sign(jwk, payload_json, protected)
        |> JOSE.JWS.compact()

      # Verification should fail
      assert {:error, :expired} = JwsDemo.JWS.Verifier.verify(compact_jws, jwk)

      # LESSON: Timestamp validation prevents replay attacks using
      # old valid signatures, even if cryptographically sound.
    end

    test "invalid signature is rejected", %{jwk: jwk} do
      # Create valid JWS then tamper with it
      payload = %{"instruction_id" => "txn_invalid", "amount" => 50_000}
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "invalid-key")

      # Tamper with signature
      tampered_jws = %{jws | "signature" => "INVALID_SIGNATURE_DATA"}

      # Verification should fail
      assert {:error, :invalid_signature} = JwsDemo.JWS.Verifier.verify(tampered_jws, jwk)

      # LESSON: Cryptographic verification ensures payload integrity.
      # Any tampering invalidates the signature.
    end
  end

  describe "performance characteristics" do
    test "signature verification is fast (< 10ms)", %{jwk: jwk} do
      # Create test JWS
      payload = %{"instruction_id" => "txn_perf", "amount" => 50_000}
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "perf-key")

      # Measure verification time
      {time_us, {:ok, _verified}} =
        :timer.tc(fn ->
          JwsDemo.JWS.Verifier.verify(jws, jwk)
        end)

      # Should be fast (< 10ms = 10,000μs)
      assert time_us < 10_000,
             "Verification took #{time_us}μs (expected < 10,000μs)"

      # LESSON: JWS verification is fast enough for real-time API
      # endpoints, adding minimal latency to request processing.
    end
  end
end
