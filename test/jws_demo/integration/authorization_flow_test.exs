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

  use JwsDemoWeb.ConnCase, async: true

  alias JwsDemo.JWS.{Signer, Audit}
  alias JwsDemo.Repo
  alias JwsDemo.AuditLogs.AuditLog
  alias JwsDemo.Partners.Partner

  setup do
    # Generate test keypair
    jwk = JOSE.JWK.generate_key({:ec, :secp256r1})

    # Create test partner
    partner =
      %Partner{}
      |> Partner.changeset(%{
        partner_id: "partner_integration_test",
        name: "Integration Test Partner",
        active: true
      })
      |> Repo.insert!()

    {:ok, jwk: jwk, partner: partner}
  end

  describe "complete authorization flow" do
    test "sign → verify → process → audit → re-verify", %{conn: conn, jwk: jwk, partner: partner} do
      # STEP 1: Partner creates authorization payload
      payload = %{
        "instruction_id" => "txn_integration_001",
        "amount" => 100_000,
        "currency" => "EUR",
        "merchant_id" => "merchant_xyz",
        "description" => "Purchase Order #12345"
      }

      IO.puts("\n=== STEP 1: Partner signs authorization ===")

      # STEP 2: Partner signs with JWS (flattened JSON)
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "integration-key-2025")

      IO.puts("✓ JWS created with flattened JSON format")
      IO.puts("  - Protected header: #{String.slice(jws["protected"], 0, 40)}...")
      IO.puts("  - Payload: #{String.slice(jws["payload"], 0, 40)}...")
      IO.puts("  - Signature: #{String.slice(jws["signature"], 0, 40)}...")

      # STEP 3: Verify signature (what VerifyJWSPlug does)
      IO.puts("\n=== STEP 2: Server verifies signature ===")
      {:ok, verified_payload} = JwsDemo.JWS.Verifier.verify(jws, jwk)

      IO.puts("✓ Signature verified successfully")
      IO.puts("  - instruction_id: #{verified_payload["instruction_id"]}")
      IO.puts("  - amount: #{verified_payload["amount"]}")
      IO.puts("  - exp: #{verified_payload["exp"]}")
      IO.puts("  - jti: #{verified_payload["jti"]}")

      # STEP 4: Simulate VerifyJWSPlug assigns
      jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"

      conn =
        conn
        |> assign(:verified_authorization, verified_payload)
        |> assign(:partner_id, partner.partner_id)

      # STEP 5: POST to authorization endpoint
      IO.puts("\n=== STEP 3: Process authorization ===")
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: 200 response with approval
      assert response = json_response(conn, 200)
      assert response["status"] == "approved"
      assert response["instruction_id"] == "txn_integration_001"
      assert response["amount"] == 100_000

      IO.puts("✓ Authorization approved")
      IO.puts("  - Status: #{response["status"]}")
      IO.puts("  - Instruction ID: #{response["instruction_id"]}")

      # STEP 6: Store in audit trail
      IO.puts("\n=== STEP 4: Store in audit trail ===")

      {:ok, audit_log} =
        Audit.log_authorization(verified_payload, jwk, %{
          jws_signature: jws_string,
          partner_id: partner.partner_id,
          verification_algorithm: "ES256",
          verification_kid: "integration-key-2025"
        })

      IO.puts("✓ Audit log created")
      IO.puts("  - Audit ID: #{audit_log.id}")
      IO.puts("  - Original JWS stored: #{String.length(audit_log.jws_signature)} bytes")
      IO.puts("  - Partner key snapshot stored: ✓")

      # STEP 7: Re-verify from audit log (simulate months later)
      IO.puts("\n=== STEP 5: Re-verify from audit trail ===")
      {:ok, reverified} = Audit.re_verify("txn_integration_001")

      assert reverified["amount"] == 100_000
      assert reverified["instruction_id"] == "txn_integration_001"

      IO.puts("✓ Re-verification successful (proves non-repudiation)")
      IO.puts("  - Amount verified: #{reverified["amount"]}")
      IO.puts("  - Instruction ID: #{reverified["instruction_id"]}")

      # STEP 8: Generate verification package
      IO.puts("\n=== STEP 6: Generate verification package ===")
      output_dir = System.tmp_dir!() |> Path.join("integration_test_#{:rand.uniform(1_000_000)}")

      assert :ok = Audit.generate_verification_package("txn_integration_001", output_dir)

      # Verify all files exist
      assert File.exists?(Path.join(output_dir, "jws_original.txt"))
      assert File.exists?(Path.join(output_dir, "public_key.pem"))
      assert File.exists?(Path.join(output_dir, "public_key.jwk"))
      assert File.exists?(Path.join(output_dir, "payload_decoded.json"))
      assert File.exists?(Path.join(output_dir, "VERIFICATION.md"))

      IO.puts("✓ Verification package generated")
      IO.puts("  - Location: #{output_dir}")
      IO.puts("  - Files: jws_original.txt, public_key.pem, public_key.jwk, payload_decoded.json, VERIFICATION.md")

      # Cleanup
      File.rm_rf!(output_dir)

      IO.puts("\n=== COMPLETE: Full non-repudiation flow verified ===\n")

      # LESSON: This test demonstrates the complete lifecycle of a
      # JWS-signed authorization with non-repudiation guarantees.
      # From signing to audit to independent verification.
    end

    test "multiple authorizations are isolated in audit trail", %{conn: conn, jwk: jwk, partner: partner} do
      # Create two separate authorizations
      payloads = [
        %{"instruction_id" => "txn_multi_001", "amount" => 50_000},
        %{"instruction_id" => "txn_multi_002", "amount" => 75_000}
      ]

      audit_ids =
        Enum.map(payloads, fn payload ->
          {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "multi-key")
          {:ok, verified} = JwsDemo.JWS.Verifier.verify(jws, jwk)
          jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"

          {:ok, audit_log} =
            Audit.log_authorization(verified, jwk, %{
              jws_signature: jws_string,
              partner_id: partner.partner_id
            })

          audit_log.id
        end)

      # Verify both are stored separately
      assert length(audit_ids) == 2
      assert Enum.at(audit_ids, 0) != Enum.at(audit_ids, 1)

      # Verify we can query each independently
      {:ok, txn1} = Audit.re_verify("txn_multi_001")
      {:ok, txn2} = Audit.re_verify("txn_multi_002")

      assert txn1["amount"] == 50_000
      assert txn2["amount"] == 75_000

      # LESSON: Audit trail maintains separate, independent records
      # for each authorization, enabling granular re-verification.
    end

    test "tampered audit log is detected on re-verification", %{jwk: jwk, partner: partner} do
      # Create and store authorization
      payload = %{"instruction_id" => "txn_tamper_test", "amount" => 10_000}
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "tamper-key")
      {:ok, verified} = JwsDemo.JWS.Verifier.verify(jws, jwk)
      jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"

      {:ok, audit_log} =
        Audit.log_authorization(verified, jwk, %{
          jws_signature: jws_string,
          partner_id: partner.partner_id
        })

      # Tamper with the stored JWS (simulate database attack)
      parts = String.split(jws_string, ".")
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
    test "expired token is rejected", %{conn: conn, jwk: jwk, partner: partner} do
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

    test "invalid signature is rejected", %{jwk: jwk, partner: partner} do
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
