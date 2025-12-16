defmodule JwsDemo.JWS.SignerTest do
  use ExUnit.Case, async: true

  alias JwsDemo.JWS.Signer

  # Generate a test keypair for signing
  setup do
    # Generate ES256 keypair (P-256 curve) using JOSE
    jwk = JOSE.JWK.generate_key({:ec, :secp256r1})

    {:ok, jwk: jwk}
  end

  describe "sign_flattened/3" do
    test "creates valid flattened JSON signature", %{jwk: jwk} do
      # SETUP: Create test payload
      # This demonstrates Post 2 signing with ES256
      payload = %{
        "instruction_id" => "txn_123",
        "amount" => 50_000,
        "currency" => "EUR",
        "merchant_id" => "merch_789"
      }

      # SIGN: Create JWS signature with flattened JSON
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key-2025-01")

      # VERIFY: Should have flattened JSON structure
      assert Map.has_key?(jws, "payload")
      assert Map.has_key?(jws, "protected")
      assert Map.has_key?(jws, "signature")

      # VERIFY: Protected header should contain algorithm and kid
      protected_json = Base.url_decode64!(jws["protected"], padding: false)
      protected = Jason.decode!(protected_json)
      assert protected["alg"] == "ES256"
      assert protected["kid"] == "test-key-2025-01"
      assert protected["typ"] == "JWT"

      # VERIFY: Payload should be Base64URL encoded
      payload_json = Base.url_decode64!(jws["payload"], padding: false)
      decoded_payload = Jason.decode!(payload_json)

      # Original fields preserved
      assert decoded_payload["instruction_id"] == "txn_123"
      assert decoded_payload["amount"] == 50_000

      # LESSON: This demonstrates flattened JSON serialization, which is
      # more readable and better for authorization request bodies (Post 2).
    end

    test "includes required claims (iat, exp, jti)", %{jwk: jwk} do
      # SETUP
      payload = %{"amount" => 30_000}

      # SIGN
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key")

      # VERIFY: Automatic claims are added
      payload_json = Base.url_decode64!(jws["payload"], padding: false)
      decoded = Jason.decode!(payload_json)

      assert Map.has_key?(decoded, "iat")
      assert Map.has_key?(decoded, "exp")
      assert Map.has_key?(decoded, "jti")

      # iat should be recent (within 5 seconds)
      now = System.system_time(:second)
      assert abs(decoded["iat"] - now) < 5

      # exp should be 5 minutes from iat (default)
      assert decoded["exp"] == decoded["iat"] + 300

      # jti should be a valid UUID
      assert is_binary(decoded["jti"])
      assert String.length(decoded["jti"]) == 36

      # LESSON: Automatic claim enrichment prevents common mistakes.
      # iat/exp enable clock skew validation, jti enables replay protection.
    end

    test "supports custom expiration time", %{jwk: jwk} do
      # SIGN with 1-hour expiration
      {:ok, jws} =
        Signer.sign_flattened(
          %{"amount" => 10_000},
          jwk,
          kid: "test-key",
          exp_seconds: 3600
        )

      # VERIFY
      payload_json = Base.url_decode64!(jws["payload"], padding: false)
      decoded = Jason.decode!(payload_json)

      assert decoded["exp"] == decoded["iat"] + 3600
    end
  end

  describe "sign_compact/3" do
    test "creates valid compact signature", %{jwk: jwk} do
      # SETUP
      payload = %{"instruction_id" => "txn_456", "amount" => 75_000}

      # SIGN: Create compact JWS
      {:ok, compact_jws} = Signer.sign_compact(payload, jwk, kid: "test-key-compact")

      # VERIFY: Compact format has 3 dot-separated parts
      parts = String.split(compact_jws, ".")
      assert length(parts) == 3

      [header_b64, payload_b64, _signature_b64] = parts

      # VERIFY: Header contains algorithm and kid
      header_json = Base.url_decode64!(header_b64, padding: false)
      header = Jason.decode!(header_json)
      assert header["alg"] == "ES256"
      assert header["kid"] == "test-key-compact"

      # VERIFY: Payload is intact
      payload_json = Base.url_decode64!(payload_b64, padding: false)
      decoded = Jason.decode!(payload_json)
      assert decoded["instruction_id"] == "txn_456"
      assert decoded["amount"] == 75_000

      # LESSON: Compact serialization is better for HTTP headers and tokens.
      # Smaller size, but less readable than flattened JSON.
    end
  end
end
