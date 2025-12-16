defmodule JwsDemo.JWS.VerifierTest do
  use ExUnit.Case, async: true

  alias JwsDemo.JWS.{Signer, Verifier}

  # Generate test keypairs for verification testing
  setup do
    # Generate ES256 keypair for valid partner
    partner_jwk = JOSE.JWK.generate_key({:ec, :secp256r1})

    # Generate separate keypair for "wrong key" tests
    wrong_jwk = JOSE.JWK.generate_key({:ec, :secp256r1})

    {:ok, partner_jwk: partner_jwk, wrong_jwk: wrong_jwk}
  end

  describe "verify/3 - successful verification" do
    test "accepts valid signature from partner", %{partner_jwk: jwk} do
      # SETUP: Create test payload
      # This demonstrates Post 2 signing with ES256
      payload = %{
        "instruction_id" => "txn_123",
        "amount" => 50_000,
        "currency" => "EUR",
        "merchant_id" => "merch_789"
      }

      # SIGN: Create JWS signature
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key")

      # VERIFY: Should succeed with correct public key
      assert {:ok, verified} = Verifier.verify(jws, jwk)

      # VERIFY: Original payload fields preserved
      assert verified["instruction_id"] == "txn_123"
      assert verified["amount"] == 50_000
      assert verified["currency"] == "EUR"

      # VERIFY: Automatic claims included
      assert Map.has_key?(verified, "iat")
      assert Map.has_key?(verified, "exp")
      assert Map.has_key?(verified, "jti")

      # LESSON: This proves the signature validates correctly and
      # the payload is intact. This is the foundation of non-repudiation.
    end

    test "accepts valid compact JWS format", %{partner_jwk: jwk} do
      # SETUP
      payload = %{"amount" => 25_000}

      # SIGN: Create compact JWS
      {:ok, compact_jws} = Signer.sign_compact(payload, jwk, kid: "test-key")

      # VERIFY: Should accept compact format
      assert {:ok, verified} = Verifier.verify(compact_jws, jwk)
      assert verified["amount"] == 25_000

      # LESSON: Verifier supports both flattened JSON and compact formats,
      # allowing flexibility for different transport mechanisms.
    end

    test "accepts 2-minute clock skew", %{partner_jwk: jwk} do
      # SETUP: Create token that expired 2 minutes ago
      now = System.system_time(:second)

      payload = %{
        "instruction_id" => "txn_456",
        "iat" => now - 240,
        "exp" => now - 120,
        "jti" => UUID.uuid4()
      }

      payload_json = Jason.encode!(payload, pretty: false)
      protected = %{"alg" => "ES256", "typ" => "JWT", "kid" => "test-key"}

      {_alg, compact_jws} =
        JOSE.JWS.sign(jwk, payload_json, protected)
        |> JOSE.JWS.compact()

      # VERIFY: Should accept with 5-minute clock skew (default)
      assert {:ok, verified} = Verifier.verify(compact_jws, jwk)
      assert verified["instruction_id"] == "txn_456"

      # LESSON: Clock skew tolerance handles server time drift.
      # 2 minutes is within the default 5-minute tolerance.
    end
  end

  describe "verify/3 - cryptographic failures" do
    test "rejects tampered payload", %{partner_jwk: jwk} do
      # SETUP: Create valid JWS
      payload = %{"amount" => 50_000}
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key")

      # TAMPER: Modify the payload (simulate attacker changing amount)
      tampered_payload =
        jws["payload"]
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()
        |> Map.put("amount", 99_999)
        |> Jason.encode!(pretty: false)
        |> Base.url_encode64(padding: false)

      tampered_jws = %{jws | "payload" => tampered_payload}

      # VERIFY: Should reject tampered payload
      assert {:error, :invalid_signature} = Verifier.verify(tampered_jws, jwk)

      # LESSON: Any modification to the payload invalidates the signature.
      # This is the cryptographic integrity guarantee of JWS.
    end

    test "rejects signature from wrong key", %{partner_jwk: partner_jwk, wrong_jwk: wrong_jwk} do
      # SETUP: Partner A signs with their key
      payload = %{"instruction_id" => "txn_789", "amount" => 30_000}
      {:ok, jws} = Signer.sign_flattened(payload, partner_jwk, kid: "partner-a")

      # VERIFY: Try to verify with Partner B's key
      assert {:error, :invalid_signature} = Verifier.verify(jws, wrong_jwk)

      # LESSON: Signature verification proves the private key holder created it.
      # Using the wrong public key fails verification, preventing key confusion attacks.
    end
  end

  describe "verify/3 - algorithm security" do
    test "rejects 'none' algorithm", %{partner_jwk: jwk} do
      # ATTACK: Craft JWS with 'none' algorithm (no signature)
      payload = %{"amount" => 999_999, "iat" => System.system_time(:second)}
      payload_json = Jason.encode!(payload, pretty: false)
      payload_b64 = Base.url_encode64(payload_json, padding: false)

      # Create header with 'none' algorithm
      header = %{"alg" => "none", "typ" => "JWT"}
      header_json = Jason.encode!(header, pretty: false)
      header_b64 = Base.url_encode64(header_json, padding: false)

      # 'none' algorithm has empty signature
      malicious_jws = "#{header_b64}.#{payload_b64}."

      # VERIFY: Should reject 'none' algorithm
      assert {:error, :algorithm_not_allowed} = Verifier.verify(malicious_jws, jwk)

      # LESSON: The infamous 'none' algorithm attack allows unsigned JWS.
      # ALWAYS enforce algorithm whitelists to prevent this attack.
    end

    test "rejects algorithm not in whitelist", %{partner_jwk: jwk} do
      # SETUP: Create token with HS256 (HMAC) instead of ES256
      payload = %{"amount" => 50_000, "iat" => System.system_time(:second)}
      payload_json = Jason.encode!(payload, pretty: false)

      # Use HS256 algorithm (symmetric)
      protected = %{"alg" => "HS256", "typ" => "JWT", "kid" => "test-key"}

      # Sign with HMAC (for demonstration - would normally use a symmetric key)
      {_alg, hs256_jws} =
        JOSE.JWS.sign(JOSE.JWK.from(%{"kty" => "oct", "k" => "test"}), payload_json, protected)
        |> JOSE.JWS.compact()

      # VERIFY: Should reject HS256 (only ES256 allowed by default)
      assert {:error, :algorithm_not_allowed} = Verifier.verify(hs256_jws, jwk)

      # LESSON: Algorithm confusion attacks exploit systems that accept
      # multiple algorithms. Always whitelist only the algorithms you use.
    end
  end

  describe "verify/3 - timestamp validation" do
    test "rejects expired token", %{partner_jwk: jwk} do
      # SETUP: Create token that expired 10 minutes ago (beyond clock skew)
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

      # VERIFY: Should reject expired token
      assert {:error, :expired} = Verifier.verify(expired_jws, jwk)

      # LESSON: Expiration prevents replay attacks using old valid signatures.
      # Tokens expire even if cryptographically valid.
    end

    test "rejects 7-minute clock skew", %{partner_jwk: jwk} do
      # SETUP: Create token that expired 7 minutes ago
      now = System.system_time(:second)

      payload = %{
        "instruction_id" => "txn_skew",
        "amount" => 50_000,
        "iat" => now - 600,
        "exp" => now - 420,
        "jti" => UUID.uuid4()
      }

      payload_json = Jason.encode!(payload, pretty: false)
      protected = %{"alg" => "ES256", "typ" => "JWT", "kid" => "test-key"}

      {_alg, skewed_jws} =
        JOSE.JWS.sign(jwk, payload_json, protected)
        |> JOSE.JWS.compact()

      # VERIFY: Should reject (7 minutes > 5 minute default tolerance)
      assert {:error, :expired} = Verifier.verify(skewed_jws, jwk)

      # LESSON: Clock skew tolerance has limits. Too much skew indicates
      # either severe time drift or potential attack.
    end

    test "rejects token issued in future", %{partner_jwk: jwk} do
      # SETUP: Create token issued 10 minutes in the future
      now = System.system_time(:second)

      future_payload = %{
        "instruction_id" => "txn_future",
        "amount" => 50_000,
        "iat" => now + 600,
        "exp" => now + 900,
        "jti" => UUID.uuid4()
      }

      payload_json = Jason.encode!(future_payload, pretty: false)
      protected = %{"alg" => "ES256", "typ" => "JWT", "kid" => "test-key"}

      {_alg, future_jws} =
        JOSE.JWS.sign(jwk, payload_json, protected)
        |> JOSE.JWS.compact()

      # VERIFY: Should reject future-issued token
      assert {:error, :not_yet_valid} = Verifier.verify(future_jws, jwk)

      # LESSON: Rejecting future timestamps prevents attacks using
      # backdated signatures or severe clock manipulation.
    end
  end

  describe "verify/3 - JSON canonicalization" do
    test "verification fails with different JSON whitespace", %{partner_jwk: jwk} do
      # SETUP: Create payload with canonical JSON (no whitespace)
      payload = %{"amount" => 50_000, "currency" => "EUR"}

      # Signer uses canonical JSON
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key")

      # TAMPER: Re-encode payload with different whitespace
      pretty_payload_json =
        jws["payload"]
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()
        |> Jason.encode!(pretty: true)
        |> Base.url_encode64(padding: false)

      tampered_jws = %{jws | "payload" => pretty_payload_json}

      # VERIFY: Should fail because whitespace changes the signature input
      assert {:error, :invalid_signature} = Verifier.verify(tampered_jws, jwk)

      # LESSON: JSON canonicalization is CRITICAL. Even whitespace changes
      # invalidate the signature. Always use consistent JSON encoding.
    end

    test "verification succeeds using original JWS payload", %{partner_jwk: jwk} do
      # SETUP: Sign with canonical JSON
      payload = %{"amount" => 50_000, "currency" => "EUR"}
      {:ok, jws} = Signer.sign_flattened(payload, jwk, kid: "test-key")

      # VERIFY: Use the exact JWS payload as signed
      assert {:ok, verified} = Verifier.verify(jws, jwk)
      assert verified["amount"] == 50_000

      # LESSON: This is why we store the ORIGINAL JWS string in audit logs.
      # Re-creating the JWS from payload data will fail verification due to
      # JSON formatting differences. Always preserve the original signature.
    end
  end

  describe "verify/3 - error handling" do
    test "rejects invalid JWS format", %{partner_jwk: jwk} do
      # VERIFY: Malformed JWS strings
      assert {:error, :invalid_format} = Verifier.verify("not.a.valid", jwk)
      assert {:error, :invalid_format} = Verifier.verify("only-two.parts", jwk)
      assert {:error, :invalid_format} = Verifier.verify(%{"payload" => "missing fields"}, jwk)

      # LESSON: Always validate input format before attempting verification.
    end

    test "rejects invalid Base64URL encoding", %{partner_jwk: jwk} do
      # VERIFY: Invalid Base64URL
      invalid_jws = "!!!invalid!!.base64.encoding"
      assert {:error, :invalid_format} = Verifier.verify(invalid_jws, jwk)

      # LESSON: Proper error handling prevents crashes from malformed input.
    end
  end
end
