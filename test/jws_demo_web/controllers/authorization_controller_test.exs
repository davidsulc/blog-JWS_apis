defmodule JwsDemoWeb.AuthorizationControllerTest do
  use JwsDemoWeb.ConnCase, async: false

  alias JwsDemo.JWS.Signer
  alias JwsDemo.AuditLogs.AuditLog
  alias JwsDemo.Repo

  # Note: async: false because we're populating global JWKS cache ETS table

  setup do
    # Generate test keypair
    jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
    partner_id = "partner_test_#{:rand.uniform(1_000_000)}"
    kid = "test-key-2025"

    # Manually insert public key into JWKS cache for testing
    # (simulates what would happen if the cache fetched from partner's JWKS endpoint)
    now = System.system_time(:second)
    ttl = 900
    cache_key = {partner_id, kid}
    :ets.insert(:jwks_cache, {cache_key, jwk, now, ttl})

    {:ok, jwk: jwk, partner_id: partner_id, kid: kid}
  end

  describe "POST /api/v1/authorizations - successful authorization" do
    test "approves valid authorization request", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP: Create authorization payload
      payload = %{
        "instruction_id" => "txn_123",
        "amount" => 50_000,
        "currency" => "EUR",
        "merchant_id" => "merch_789"
      }

      # Sign with JWS (flattened JSON format)
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # REQUEST: POST with signed JWS
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: 200 response with approval
      assert %{
               "status" => "approved",
               "instruction_id" => "txn_123",
               "amount" => 50_000,
               "currency" => "EUR",
               "partner_id" => ^partner_id,
               "verified_at" => _verified_at,
               "jti" => _jti,
               "exp" => _exp
             } = json_response(conn, 200)

      # LESSON: VerifyJWSPlug verified the signature, controller processed
      # the authorization, and returned approval with instruction_id.
    end

    test "defaults currency to USD when not provided", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP: Payload without currency
      payload = %{
        "instruction_id" => "txn_456",
        "amount" => 25_000
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # REQUEST
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: Defaults to USD
      assert %{"currency" => "USD"} = json_response(conn, 200)

      # LESSON: Controller provides sensible defaults for optional fields.
    end

    test "includes JWT claims in response", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP
      payload = %{
        "instruction_id" => "txn_789",
        "amount" => 10_000
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # REQUEST
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: JWT claims included for audit trail
      response = json_response(conn, 200)
      assert is_binary(response["jti"])
      assert is_integer(response["exp"])

      # LESSON: Including JWT claims (jti, exp) in response enables
      # correlation between authorization and audit logs for replay protection.
    end
  end

  describe "POST /api/v1/authorizations - validation failures" do
    test "rejects authorization missing instruction_id", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP: Missing required field
      payload = %{
        "amount" => 50_000,
        "currency" => "EUR"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # REQUEST
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: 400 with missing field error
      assert %{
               "error" => "authorization_failed",
               "message" => message
             } = json_response(conn, 400)

      assert String.contains?(message, "instruction_id")

      # LESSON: Even with valid JWS signature, authorization can fail
      # business validation. Signature proves intent, validation ensures correctness.
    end

    test "rejects authorization missing amount", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP: Missing amount
      payload = %{
        "instruction_id" => "txn_no_amount",
        "currency" => "EUR"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # REQUEST
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: 400 error
      assert %{"error" => "authorization_failed"} = json_response(conn, 400)
    end

    test "rejects authorization with negative amount", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP: Invalid amount (negative)
      payload = %{
        "instruction_id" => "txn_negative",
        "amount" => -50_000
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # REQUEST
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: 400 with amount validation error
      assert %{
               "error" => "authorization_failed",
               "message" => message
             } = json_response(conn, 400)

      assert String.contains?(message, "positive")

      # LESSON: Business logic validation prevents invalid transactions
      # even when cryptographic signature is valid.
    end

    test "rejects authorization with zero amount", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP: Zero amount
      payload = %{
        "instruction_id" => "txn_zero",
        "amount" => 0
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # REQUEST
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: 400 error
      assert %{"error" => "authorization_failed"} = json_response(conn, 400)
    end

    test "rejects authorization with non-numeric amount", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP: Amount as string
      payload = %{
        "instruction_id" => "txn_string_amount",
        "amount" => "50000"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # REQUEST
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: 400 error
      assert %{
               "error" => "authorization_failed",
               "message" => message
             } = json_response(conn, 400)

      assert String.contains?(message, "number")
    end
  end

  describe "POST /api/v1/authorizations - signature verification" do
    test "rejects request with invalid signature", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP: Create valid JWS then tamper with it
      payload = %{
        "instruction_id" => "txn_tampered",
        "amount" => 50_000
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # Tamper with signature
      tampered_jws = %{jws | "signature" => "INVALID_SIGNATURE_DATA"}

      # REQUEST
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", tampered_jws)

      # VERIFY: 401 unauthorized (VerifyJWSPlug rejects invalid signature)
      assert %{"error" => error} = json_response(conn, 401)
      assert error == "verification_failed"

      # LESSON: VerifyJWSPlug rejects tampered signatures before reaching controller.
    end

    test "rejects request missing X-Partner-ID header", %{conn: conn, jwk: jwk, kid: kid} do
      # SETUP: Valid JWS but no partner ID
      payload = %{
        "instruction_id" => "txn_no_partner",
        "amount" => 50_000
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # REQUEST: No X-Partner-ID header
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: 401 unauthorized
      assert %{"error" => error} = json_response(conn, 401)
      assert error == "missing_header"

      # LESSON: VerifyJWSPlug enforces required headers before signature verification.
    end

    test "rejects request with unknown kid", %{conn: conn, jwk: jwk, partner_id: partner_id} do
      # SETUP: Sign with unknown kid (not in cache)
      payload = %{
        "instruction_id" => "txn_unknown_kid",
        "amount" => 50_000
      }

      unknown_kid = "unknown-key-9999"
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: unknown_kid)

      # REQUEST
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

      # VERIFY: 401 unauthorized (key not found in cache)
      assert %{"error" => error} = json_response(conn, 401)
      assert error == "key_fetch_failed"

      # LESSON: VerifyJWSPlug rejects requests with unknown key IDs.
    end
  end

  describe "POST /api/v1/authorizations - audit trail" do
    test "creates audit log for approved authorization", %{conn: conn, jwk: jwk, partner_id: partner_id, kid: kid} do
      # SETUP: Create signed authorization
      payload = %{
        "instruction_id" => "txn_audit_test_123",
        "amount" => 100_000,
        "currency" => "EUR"
      }

      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: kid)

      # BEFORE: No audit logs exist for this instruction
      assert Repo.get_by(AuditLog, instruction_id: "txn_audit_test_123") == nil

      # REQUEST: Create authorization
      conn =
        conn
        |> put_req_header("x-partner-id", partner_id)
        |> put_req_header("content-type", "application/json")
        |> post(~p"/api/v1/authorizations", jws)

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
