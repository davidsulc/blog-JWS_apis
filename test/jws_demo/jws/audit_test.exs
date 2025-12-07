defmodule JwsDemo.JWS.AuditTest do
  use JwsDemo.DataCase, async: true

  alias JwsDemo.JWS.{Audit, Signer}
  alias JwsDemo.AuditLogs.AuditLog
  alias JwsDemo.Repo

  setup do
    # Generate test keypair
    jwk = JOSE.JWK.generate_key({:ec, :secp256r1})

    # Create test partner
    partner =
      %JwsDemo.Partners.Partner{}
      |> JwsDemo.Partners.Partner.changeset(%{
        partner_id: "partner_test",
        name: "Test Partner Inc",
        active: true
      })
      |> Repo.insert!()

    {:ok, jwk: jwk, partner: partner}
  end

  describe "log_authorization/3" do
    test "stores authorization with original JWS and partner key", %{jwk: jwk} do
      # SETUP: Create signed authorization
      payload = %{
        "instruction_id" => "txn_audit_123",
        "amount" => 50_000,
        "currency" => "EUR"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key")

      # Verify to get verified payload
      {:ok, verified_payload} = JwsDemo.JWS.Verifier.verify(jws, jwk)

      # Convert JWS to string for storage
      jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"

      # LOG: Store in audit trail
      {:ok, audit_log} =
        Audit.log_authorization(verified_payload, jwk, %{
          jws_signature: jws_string,
          partner_id: "partner_abc",
          verification_algorithm: "ES256",
          verification_kid: "test-key"
        })

      # VERIFY: Audit log created
      assert audit_log.id
      assert audit_log.instruction_id == "txn_audit_123"
      assert audit_log.jws_signature == jws_string
      assert audit_log.partner_public_key != nil
      assert audit_log.payload["amount"] == 50_000
      assert audit_log.verification_algorithm == "ES256"
      assert audit_log.verification_kid == "test-key"

      # LESSON: Audit log stores ORIGINAL JWS and partner key snapshot
      # for future re-verification, even after partner rotates keys.
    end

    test "stores payload for querying", %{jwk: jwk} do
      # SETUP
      payload = %{
        "instruction_id" => "txn_query_456",
        "amount" => 25_000,
        "merchant_id" => "merch_123"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key")
      {:ok, verified_payload} = JwsDemo.JWS.Verifier.verify(jws, jwk)
      jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"

      # LOG
      {:ok, _audit_log} =
        Audit.log_authorization(verified_payload, jwk, %{
          jws_signature: jws_string,
          partner_id: "partner_xyz"
        })

      # VERIFY: Can query by instruction_id
      audit_log = Repo.get_by(AuditLog, instruction_id: "txn_query_456")
      assert audit_log.payload["merchant_id"] == "merch_123"

      # LESSON: Payload stored in JSONB allows efficient querying
      # for business intelligence and reporting.
    end
  end

  describe "re_verify/1" do
    test "successfully re-verifies using stored JWS and key", %{jwk: jwk} do
      # SETUP: Store authorization
      payload = %{
        "instruction_id" => "txn_reverify_789",
        "amount" => 75_000,
        "currency" => "GBP"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key")
      {:ok, verified_payload} = JwsDemo.JWS.Verifier.verify(jws, jwk)
      jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"

      {:ok, _audit_log} =
        Audit.log_authorization(verified_payload, jwk, %{
          jws_signature: jws_string,
          partner_id: "partner_reverify"
        })

      # RE-VERIFY: Simulate re-verification months later
      {:ok, reverified} = Audit.re_verify("txn_reverify_789")

      # VERIFY: Payload matches original
      assert reverified["amount"] == 75_000
      assert reverified["currency"] == "GBP"
      assert reverified["instruction_id"] == "txn_reverify_789"

      # LESSON: Re-verification proves the authorization is still valid
      # even years later, using the exact original JWS and key snapshot.
      # This is the "forever proof" of non-repudiation.
    end

    test "fails re-verification for non-existent instruction_id" do
      # RE-VERIFY: Non-existent authorization
      assert {:error, :audit_log_not_found} = Audit.re_verify("nonexistent_txn")

      # LESSON: Re-verification requires audit log to exist.
    end

    test "detects tampered JWS in audit log", %{jwk: jwk} do
      # SETUP: Store authorization
      payload = %{
        "instruction_id" => "txn_tamper_999",
        "amount" => 10_000
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key")
      {:ok, verified_payload} = JwsDemo.JWS.Verifier.verify(jws, jwk)
      jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"

      {:ok, audit_log} =
        Audit.log_authorization(verified_payload, jwk, %{
          jws_signature: jws_string,
          partner_id: "partner_tamper"
        })

      # TAMPER: Modify the signature part (last part of JWS)
      parts = String.split(jws_string, ".")
      original_sig = Enum.at(parts, 2)
      # Replace first character to ensure we actually tamper with it
      tampered_signature = "X" <> String.slice(original_sig, 1, String.length(original_sig) - 1)
      tampered_jws = "#{Enum.at(parts, 0)}.#{Enum.at(parts, 1)}.#{tampered_signature}"

      audit_log
      |> Ecto.Changeset.change(jws_signature: tampered_jws)
      |> Repo.update!()

      # RE-VERIFY: Should fail
      assert {:error, {:verification_failed, :invalid_signature}} =
               Audit.re_verify("txn_tamper_999")

      # LESSON: Re-verification detects any tampering with the stored JWS.
      # This protects the audit trail's integrity.
    end
  end

  describe "generate_verification_package/2" do
    test "creates verification package with all required files", %{jwk: jwk} do
      # SETUP: Store authorization
      payload = %{
        "instruction_id" => "txn_package_111",
        "amount" => 100_000,
        "currency" => "USD"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "package-key")
      {:ok, verified_payload} = JwsDemo.JWS.Verifier.verify(jws, jwk)
      jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"

      {:ok, _audit_log} =
        Audit.log_authorization(verified_payload, jwk, %{
          jws_signature: jws_string,
          partner_id: "partner_package",
          verification_kid: "package-key"
        })

      # GENERATE: Create verification package
      output_dir = System.tmp_dir!() |> Path.join("audit_test_#{:rand.uniform(1_000_000)}")

      assert :ok = Audit.generate_verification_package("txn_package_111", output_dir)

      # VERIFY: All required files exist
      assert File.exists?(Path.join(output_dir, "jws_original.txt"))
      assert File.exists?(Path.join(output_dir, "public_key.pem"))
      assert File.exists?(Path.join(output_dir, "public_key.jwk"))
      assert File.exists?(Path.join(output_dir, "payload_decoded.json"))
      assert File.exists?(Path.join(output_dir, "VERIFICATION.md"))

      # VERIFY: JWS file contains original signature
      jws_content = File.read!(Path.join(output_dir, "jws_original.txt"))
      assert jws_content == jws_string

      # VERIFY: Payload file is valid JSON
      payload_json = File.read!(Path.join(output_dir, "payload_decoded.json"))
      decoded = Jason.decode!(payload_json)
      assert decoded["amount"] == 100_000

      # VERIFY: Public key is valid PEM
      pem_content = File.read!(Path.join(output_dir, "public_key.pem"))
      assert String.contains?(pem_content, "BEGIN PUBLIC KEY")
      assert String.contains?(pem_content, "END PUBLIC KEY")

      # VERIFY: Verification instructions exist
      verification_md = File.read!(Path.join(output_dir, "VERIFICATION.md"))
      assert String.contains?(verification_md, "txn_package_111")
      assert String.contains?(verification_md, "OpenSSL")

      # Cleanup
      File.rm_rf!(output_dir)

      # LESSON: Verification package contains everything needed for
      # independent audit without access to our codebase or systems.
    end

    test "verification package enables independent verification", %{jwk: jwk} do
      # SETUP: Store authorization
      payload = %{"instruction_id" => "txn_independent_222", "amount" => 50_000}

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "ind-key")
      {:ok, verified_payload} = JwsDemo.JWS.Verifier.verify(jws, jwk)
      jws_string = "#{jws["protected"]}.#{jws["payload"]}.#{jws["signature"]}"

      {:ok, _audit_log} =
        Audit.log_authorization(verified_payload, jwk, %{
          jws_signature: jws_string,
          partner_id: "partner_ind"
        })

      # GENERATE: Package
      output_dir = System.tmp_dir!() |> Path.join("audit_ind_#{:rand.uniform(1_000_000)}")
      assert :ok = Audit.generate_verification_package("txn_independent_222", output_dir)

      # VERIFY: Can load JWK from generated file
      jwk_json = File.read!(Path.join(output_dir, "public_key.jwk"))
      loaded_jwk = Jason.decode!(jwk_json) |> JOSE.JWK.from()

      # VERIFY: Can verify JWS using loaded key
      jws_from_file = File.read!(Path.join(output_dir, "jws_original.txt"))
      assert {:ok, reverified} = JwsDemo.JWS.Verifier.verify(jws_from_file, loaded_jwk)
      assert reverified["amount"] == 50_000

      # Cleanup
      File.rm_rf!(output_dir)

      # LESSON: Verification package is self-contained. An auditor can
      # verify the signature using only the files in the package.
    end

    test "returns error for non-existent instruction_id" do
      output_dir = System.tmp_dir!() |> Path.join("audit_noexist")

      assert {:error, :audit_log_not_found} =
               Audit.generate_verification_package("nonexistent", output_dir)

      # LESSON: Package generation requires valid audit log.
    end
  end
end
