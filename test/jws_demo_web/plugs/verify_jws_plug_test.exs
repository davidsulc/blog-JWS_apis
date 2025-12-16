defmodule JwsDemoWeb.VerifyJWSPlugTest do
  use JwsDemoWeb.ConnCase, async: true

  alias JwsDemoWeb.VerifyJWSPlug
  alias JwsDemo.JWS.Signer

  defmodule Instruction do
    defstruct [:id, :currency, :amount]

    def new!(%{} = data), do: struct!(__MODULE__, data)

    def to_payload(%__MODULE__{id: id, currency: currency, amount: amt}) do
      %{
        "instruction_id" => id,
        "amount" => amt,
        "currency" => currency
      }
    end

    def verify_conn_verified_authz(%__MODULE__{} = instruction, %Plug.Conn{} = conn) do
      assert conn.assigns.verified_authorization["instruction_id"] == instruction.id
      assert conn.assigns.verified_authorization["amount"] == instruction.amount
      assert conn.assigns.verified_authorization["currency"] == instruction.currency
    end
  end

  setup do
    # Generate test keypair
    partner_jwk = JOSE.JWK.generate_key({:ec, :secp256r1})

    partner_id = "partner_abc"

    # Mock key provider function (takes partner_id and kid)
    get_jwk_fn = fn
      ^partner_id, _kid -> {:ok, partner_jwk}
      "unknown_partner", _kid -> {:error, :partner_not_found}
      _, _ -> {:error, :invalid_partner}
    end

    {:ok, partner_id: partner_id, partner_jwk: partner_jwk, get_jwk_fn: get_jwk_fn}
  end

  describe "call/2 - successful verification" do
    test "accepts valid JWS and assigns verified payload", %{
      conn: conn,
      partner_id: partner_id,
      partner_jwk: jwk,
      get_jwk_fn: get_jwk_fn
    } do
      instruction = Instruction.new!(%{
        id: "txn_123",
        amount: 50_000,
        currency: "EUR"
      })

      # SETUP: Create signed authorization
      {:ok, jws} =
        instruction
        |> Instruction.to_payload()
        |> Signer.sign_flattened(jwk, kid: "partner-key-2025")

      # REQUEST: Send with valid signature
      conn =
        conn
        |> setup_with(partner_id: partner_id, body: jws)
        |> VerifyJWSPlug.call(get_jwk: get_jwk_fn)

      # VERIFY: Connection not halted
      refute conn.halted

      # VERIFY: Verified payload assigned
      Instruction.verify_conn_verified_authz(instruction, conn)
      assert conn.assigns.partner_id == partner_id

      # LESSON: On successful verification, the plug assigns the verified
      # payload to conn.assigns, making it available to controllers.
    end

    test "accepts compact JWS format", %{
        conn: conn,
        partner_id: partner_id,
        partner_jwk: jwk,
        get_jwk_fn: get_jwk_fn} do
      # SETUP: Create compact JWS
      instruction = Instruction.new!(%{
        id: "txn_456",
        amount: 25_000,
        currency: "EUR"
      })

      {:ok, compact_jws} =
        instruction
        |> Instruction.to_payload()
        |> Signer.sign_compact(jwk, kid: "partner-key")

      # REQUEST: Send compact format in "jws" field
      conn =
        conn
        |> setup_with(partner_id: partner_id, body: compact_jws)
        |> VerifyJWSPlug.call(get_jwk: get_jwk_fn)

      # VERIFY: Accepted
      refute conn.halted
      Instruction.verify_conn_verified_authz(instruction, conn)
      assert conn.assigns.partner_id == partner_id

      # LESSON: Plug supports both flattened JSON and compact formats,
      # providing flexibility for different client implementations.
    end
  end

  describe "call/2 - verification failures" do
    test "rejects invalid signature with 401", %{
      conn: conn,
      partner_id: partner_id,
      partner_jwk: jwk,
      get_jwk_fn: get_jwk_fn
    } do
      # SETUP: Create valid JWS then tamper with it
      payload = %{"amount" => 50_000}
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "partner-key")

      # TAMPER: Modify signature
      tampered_jws = %{jws | "signature" => "invalid_signature_data"}

      # REQUEST: Send tampered JWS
      conn =
        conn
        |> setup_with(partner_id: partner_id, body: tampered_jws)
        |> VerifyJWSPlug.call(get_jwk: get_jwk_fn)

      # VERIFY: 401 response
      assert conn.status == 401
      assert conn.halted

      # VERIFY: Error response
      response = Jason.decode!(conn.resp_body)
      assert response["error"] == "verification_failed"
      assert response["partner_id"] == partner_id
      assert String.contains?(response["message"], "signature")

      # LESSON: Invalid signatures result in 401 with detailed error messages
      # for debugging while protecting against unauthorized requests.
    end

    test "rejects expired token with 401", %{
      conn: conn,
      partner_id: partner_id,
      partner_jwk: jwk,
      get_jwk_fn: get_jwk_fn
    } do
      # SETUP: Create expired token
      now = System.system_time(:second)

      expired_payload = %{
        "instruction_id" => "txn_expired",
        "amount" => 50_000,
        "iat" => now - 900,
        "exp" => now - 600,
        "jti" => UUID.uuid4()
      }

      payload_json = Jason.encode!(expired_payload, pretty: false)
      protected = %{"alg" => "ES256", "typ" => "JWT", "kid" => "test-key"}

      {_alg, expired_jws} =
        JOSE.JWS.sign(jwk, payload_json, protected)
        |> JOSE.JWS.compact()

      # REQUEST: Send expired token
      conn =
        conn
        |> setup_with(partner_id: partner_id, body: expired_jws)
        |> VerifyJWSPlug.call(get_jwk: get_jwk_fn)

      # VERIFY: 401 with expiration message
      assert conn.status == 401
      response = Jason.decode!(conn.resp_body)
      assert response["error"] == "verification_failed"
      assert String.contains?(response["message"], "expired")

      # LESSON: Timestamp validation prevents replay attacks using old signatures.
    end
  end

  describe "call/2 - request validation" do
    test "rejects missing X-Partner-ID header with 401", %{conn: conn, get_jwk_fn: get_jwk_fn} do
      # REQUEST: No partner ID header
      conn =
        conn
        |> put_req_header("content-type", "application/json")
        |> Map.put(:body_params, %{"payload" => "test"})
        |> VerifyJWSPlug.call(get_jwk: get_jwk_fn)

      # VERIFY: 401 response
      assert conn.status == 401
      assert conn.halted

      response = Jason.decode!(conn.resp_body)
      assert response["error"] == "missing_header"
      assert String.contains?(response["message"], "X-Partner-ID")

      # LESSON: Partner identification is required for key lookup.
    end

    test "rejects invalid request body with 401", %{
        conn: conn,
        partner_id: partner_id,
        get_jwk_fn: get_jwk_fn
      } do
      # REQUEST: Invalid body (not JWS format)
      conn =
        conn
        |> setup_with(partner_id: partner_id, body: %{"invalid" => "body"})
        |> VerifyJWSPlug.call(get_jwk: get_jwk_fn)

      # VERIFY: 401 response
      assert conn.status == 401

      response = Jason.decode!(conn.resp_body)
      assert response["error"] == "invalid_body"
      assert String.contains?(response["message"], "JWS")

      # LESSON: Request body must contain valid JWS structure.
    end

    test "rejects unknown partner with 401", %{
        conn: conn,
        partner_jwk: jwk,
        get_jwk_fn: get_jwk_fn
      } do
      # SETUP: Valid JWS
      {:ok, jws} = Signer.sign_flattened(%{"amount" => 50_000}, jwk, kid: "key")

      # REQUEST: Unknown partner
      conn =
        conn
        |> setup_with(partner_id:  "unknown_partner", body: jws)
        |> VerifyJWSPlug.call(get_jwk: get_jwk_fn)

      # VERIFY: 401 response
      assert conn.status == 401

      response = Jason.decode!(conn.resp_body)
      assert response["error"] == "key_fetch_failed"
      assert String.contains?(response["message"], "public key")

      # LESSON: Partner must be registered with valid public key.
    end
  end

  describe "call/2 - configuration" do
    test "returns error when get_jwk not configured", %{
        conn: conn,
        partner_id: partner_id,
        partner_jwk: jwk
      } do
      # SETUP: Valid JWS
      {:ok, jws} = Signer.sign_flattened(%{"amount" => 50_000}, jwk, kid: "key")

      # REQUEST: Plug without get_jwk option
      conn =
        conn
        |> setup_with(partner_id: partner_id, body: jws)
        |> VerifyJWSPlug.call([])

      # VERIFY: 401 with configuration error
      assert conn.status == 401

      response = Jason.decode!(conn.resp_body)
      assert response["error"] == "no_key_provider"
      assert String.contains?(response["message"], "not configured")

      # LESSON: Plug requires :get_jwk configuration for key lookup.
    end

    test "passes custom verification options", %{
      conn: conn,
      partner_id: partner_id,
      partner_jwk: jwk,
      get_jwk_fn: get_jwk_fn
    } do
      # SETUP: Token expired 2 minutes ago
      now = System.system_time(:second)

      payload = %{
        "instruction_id" => "txn_custom",
        "amount" => 50_000,
        "iat" => now - 240,
        "exp" => now - 120,
        "jti" => UUID.uuid4()
      }

      payload_json = Jason.encode!(payload, pretty: false)
      protected = %{"alg" => "ES256", "typ" => "JWT", "kid" => "test-key"}

      {_alg, skewed_jws} =
        JOSE.JWS.sign(jwk, payload_json, protected)
        |> JOSE.JWS.compact()

      # REQUEST: With custom clock_skew_seconds (1 minute)
      conn =
        conn
        |> setup_with(partner_id: partner_id, body: %{"jws" => skewed_jws})
        |> VerifyJWSPlug.call(get_jwk: get_jwk_fn, clock_skew_seconds: 60)

      # VERIFY: Rejected (2 minutes > 1 minute tolerance)
      assert conn.status == 401
      response = Jason.decode!(conn.resp_body)
      assert String.contains?(response["message"], "expired")

      # LESSON: Plug accepts custom verification options for flexibility.
    end
  end

  defp setup_with(%Plug.Conn{} = conn, opts) do
    partner_id = Keyword.fetch!(opts, :partner_id)
    body = Keyword.fetch!(opts, :body)

    conn
    |> put_req_header("x-partner-id", partner_id)
    |> put_req_header("content-type", "application/json")
    |> Map.put(:body_params, body)
  end
end
