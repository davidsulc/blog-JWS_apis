defmodule JwsDemoWeb.AuthorizationControllerTest do
  use JwsDemoWeb.ConnCase, async: true

  alias JwsDemo.JWS.Signer
  alias JwsDemo.AuditLogs.AuditLog
  alias JwsDemo.Repo

  setup do
    # Generate test keypair
    jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
    {:ok, jwk: jwk}
  end

  describe "POST /api/v1/authorizations - successful authorization" do
    test "approves valid authorization request", %{conn: conn} do
      # SETUP: Create verified authorization payload
      # In production, VerifyJWSPlug would verify and assign this
      verified_payload = %{
        "instruction_id" => "txn_123",
        "amount" => 50_000,
        "currency" => "EUR",
        "merchant_id" => "merch_789",
        "iat" => System.system_time(:second),
        "exp" => System.system_time(:second) + 300,
        "jti" => UUID.uuid4()
      }

      # Simulate VerifyJWSPlug assigns
      conn =
        conn
        |> assign(:verified_authorization, verified_payload)
        |> assign(:partner_id, "partner_abc")

      # REQUEST: Create authorization
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: 200 response with approval
      assert %{
               "status" => "approved",
               "instruction_id" => "txn_123",
               "amount" => 50_000,
               "currency" => "EUR",
               "partner_id" => "partner_abc",
               "verified_at" => _verified_at,
               "jti" => _jti,
               "exp" => _exp
             } = json_response(conn, 200)

      # LESSON: Controller processes verified authorization payload and returns
      # approval with instruction_id. The JWS signature proves non-repudiation.
    end

    test "defaults currency to USD when not provided", %{conn: conn} do
      # SETUP: Payload without currency
      verified_payload = %{
        "instruction_id" => "txn_456",
        "amount" => 25_000,
        "iat" => System.system_time(:second),
        "exp" => System.system_time(:second) + 300,
        "jti" => UUID.uuid4()
      }

      conn =
        conn
        |> assign(:verified_authorization, verified_payload)
        |> assign(:partner_id, "partner_xyz")

      # REQUEST
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: Defaults to USD
      assert %{"currency" => "USD"} = json_response(conn, 200)

      # LESSON: Controller provides sensible defaults for optional fields.
    end

    test "includes JWT claims in response", %{conn: conn} do
      # SETUP
      jti = UUID.uuid4()
      exp = System.system_time(:second) + 300

      verified_payload = %{
        "instruction_id" => "txn_789",
        "amount" => 10_000,
        "iat" => System.system_time(:second),
        "exp" => exp,
        "jti" => jti
      }

      conn =
        conn
        |> assign(:verified_authorization, verified_payload)
        |> assign(:partner_id, "partner_test")

      # REQUEST
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: JWT claims included for audit trail
      response = json_response(conn, 200)
      assert response["jti"] == jti
      assert response["exp"] == exp

      # LESSON: Including JWT claims (jti, exp) in response enables
      # correlation between authorization and audit logs for replay protection.
    end
  end

  describe "POST /api/v1/authorizations - validation failures" do
    test "rejects authorization missing instruction_id", %{conn: conn} do
      # SETUP: Missing required field
      verified_payload = %{
        "amount" => 50_000,
        "currency" => "EUR",
        "iat" => System.system_time(:second),
        "exp" => System.system_time(:second) + 300,
        "jti" => UUID.uuid4()
      }

      conn =
        conn
        |> assign(:verified_authorization, verified_payload)
        |> assign(:partner_id, "partner_abc")

      # REQUEST
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: 400 with missing field error
      assert %{
               "error" => "authorization_failed",
               "message" => message
             } = json_response(conn, 400)

      assert String.contains?(message, "instruction_id")

      # LESSON: Even with valid JWS signature, authorization can fail
      # business validation. Signature proves intent, validation ensures correctness.
    end

    test "rejects authorization missing amount", %{conn: conn} do
      # SETUP: Missing amount
      verified_payload = %{
        "instruction_id" => "txn_no_amount",
        "currency" => "EUR",
        "iat" => System.system_time(:second),
        "exp" => System.system_time(:second) + 300,
        "jti" => UUID.uuid4()
      }

      conn =
        conn
        |> assign(:verified_authorization, verified_payload)
        |> assign(:partner_id, "partner_abc")

      # REQUEST
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: 400 error
      assert %{"error" => "authorization_failed"} = json_response(conn, 400)
    end

    test "rejects authorization with negative amount", %{conn: conn} do
      # SETUP: Invalid amount (negative)
      verified_payload = %{
        "instruction_id" => "txn_negative",
        "amount" => -50_000,
        "iat" => System.system_time(:second),
        "exp" => System.system_time(:second) + 300,
        "jti" => UUID.uuid4()
      }

      conn =
        conn
        |> assign(:verified_authorization, verified_payload)
        |> assign(:partner_id, "partner_abc")

      # REQUEST
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: 400 with amount validation error
      assert %{
               "error" => "authorization_failed",
               "message" => message
             } = json_response(conn, 400)

      assert String.contains?(message, "positive")

      # LESSON: Business logic validation prevents invalid transactions
      # even when cryptographic signature is valid.
    end

    test "rejects authorization with zero amount", %{conn: conn} do
      # SETUP: Zero amount
      verified_payload = %{
        "instruction_id" => "txn_zero",
        "amount" => 0,
        "iat" => System.system_time(:second),
        "exp" => System.system_time(:second) + 300,
        "jti" => UUID.uuid4()
      }

      conn =
        conn
        |> assign(:verified_authorization, verified_payload)
        |> assign(:partner_id, "partner_abc")

      # REQUEST
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: 400 error
      assert %{"error" => "authorization_failed"} = json_response(conn, 400)
    end

    test "rejects authorization with non-numeric amount", %{conn: conn} do
      # SETUP: Amount as string
      verified_payload = %{
        "instruction_id" => "txn_string_amount",
        "amount" => "50000",
        "iat" => System.system_time(:second),
        "exp" => System.system_time(:second) + 300,
        "jti" => UUID.uuid4()
      }

      conn =
        conn
        |> assign(:verified_authorization, verified_payload)
        |> assign(:partner_id, "partner_abc")

      # REQUEST
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: 400 error
      assert %{
               "error" => "authorization_failed",
               "message" => message
             } = json_response(conn, 400)

      assert String.contains?(message, "number")
    end
  end

  describe "POST /api/v1/authorizations - integration with JWS" do
    test "processes signed request (integration test)", %{conn: conn, jwk: jwk} do
      # SETUP: Create full signed authorization
      # This demonstrates the complete flow that will be used in production
      payload = %{
        "instruction_id" => "txn_integration_123",
        "amount" => 75_000,
        "currency" => "GBP",
        "merchant_id" => "merch_integration"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "partner-key-2025")

      # Manually verify (simulating what VerifyJWSPlug will do)
      {:ok, verified} = JwsDemo.JWS.Verifier.verify(jws, jwk)

      # Assign verified payload (simulating VerifyJWSPlug)
      conn =
        conn
        |> assign(:verified_authorization, verified)
        |> assign(:partner_id, "partner_integration")

      # REQUEST
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: Authorization approved with all fields
      response = json_response(conn, 200)
      assert response["status"] == "approved"
      assert response["instruction_id"] == "txn_integration_123"
      assert response["amount"] == 75_000
      assert response["currency"] == "GBP"
      assert response["partner_id"] == "partner_integration"

      # VERIFY: JWT claims included
      assert is_binary(response["jti"])
      assert is_integer(response["exp"])

      # LESSON: This integration test demonstrates the complete flow:
      # 1. Partner signs authorization with JWS
      # 2. Server verifies signature
      # 3. Controller processes verified authorization
      # 4. Returns approval with proof of verification
      # This proves non-repudiation: partner cannot deny this authorization.
    end

    test "creates audit log for approved authorization", %{conn: conn, jwk: jwk} do
      # SETUP: Create signed authorization
      payload = %{
        "instruction_id" => "txn_audit_test_123",
        "amount" => 100_000,
        "currency" => "EUR"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "audit-test-key")
      {:ok, verified} = JwsDemo.JWS.Verifier.verify(jws, jwk)

      # Simulate VerifyJWSPlug assigns (including audit data)
      conn =
        conn
        |> assign(:verified_authorization, verified)
        |> assign(:partner_id, "partner_audit_test")
        |> assign(:jws_original, jws)
        |> assign(:partner_jwk, jwk)

      # BEFORE: No audit logs exist for this instruction
      assert Repo.get_by(AuditLog, instruction_id: "txn_audit_test_123") == nil

      # REQUEST: Create authorization
      conn = post(conn, ~p"/api/v1/authorizations")

      # VERIFY: Authorization approved
      assert %{"status" => "approved"} = json_response(conn, 200)

      # VERIFY: Audit log was created
      audit_log = Repo.get_by(AuditLog, instruction_id: "txn_audit_test_123")
      assert audit_log != nil
      assert audit_log.instruction_id == "txn_audit_test_123"
      assert audit_log.verification_algorithm == "ES256"

      # VERIFY: Audit log contains original JWS signature
      assert is_binary(audit_log.jws_signature)
      assert String.contains?(audit_log.jws_signature, ".")

      # VERIFY: Audit log contains partner public key snapshot
      assert is_map(audit_log.partner_public_key)
      assert audit_log.partner_public_key["kty"] == "EC"

      # VERIFY: Audit log contains verified payload
      assert audit_log.payload["instruction_id"] == "txn_audit_test_123"
      assert audit_log.payload["amount"] == 100_000

      # LESSON: Every approved authorization creates an immutable audit log.
      # This enables non-repudiation: we store the original JWS signature
      # and partner's public key, allowing re-verification years later
      # even if the partner rotates their keys.
    end
  end
end
