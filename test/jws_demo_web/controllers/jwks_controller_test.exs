defmodule JwsDemoWeb.JWKSControllerTest do
  use JwsDemoWeb.ConnCase, async: true

  alias JwsDemo.JWS.JWKSPublisher

  describe "GET /.well-known/jwks.json" do
    test "returns valid JWKS with public keys", %{conn: conn} do
      # REQUEST: Fetch JWKS
      conn = get(conn, ~p"/.well-known/jwks.json")

      # VERIFY: 200 response
      assert %{"keys" => keys} = json_response(conn, 200)

      # VERIFY: At least one key returned
      assert length(keys) > 0

      # VERIFY: First key has required JWKS fields
      [first_key | _] = keys
      assert first_key["kty"] == "EC"
      assert first_key["use"] == "sig"
      assert first_key["alg"] == "ES256"
      assert first_key["crv"] == "P-256"
      assert is_binary(first_key["kid"])
      assert is_binary(first_key["x"])
      assert is_binary(first_key["y"])

      # LESSON: JWKS endpoint publishes public keys in standard format,
      # allowing partners to verify our JWS signatures.
    end

    test "returns proper cache control headers", %{conn: conn} do
      # REQUEST: Fetch JWKS
      conn = get(conn, ~p"/.well-known/jwks.json")

      # VERIFY: Cache-Control header
      cache_control = get_resp_header(conn, "cache-control")
      assert cache_control == ["public, max-age=600, must-revalidate"]

      # LESSON: Cache headers allow partners to cache keys for 10 minutes,
      # reducing load on our server while ensuring fresh keys during rotation.
    end

    test "returns application/json content type", %{conn: conn} do
      # REQUEST
      conn = get(conn, ~p"/.well-known/jwks.json")

      # VERIFY: Content-Type header
      content_type = get_resp_header(conn, "content-type")
      assert ["application/json; charset=utf-8"] = content_type

      # LESSON: Proper content-type ensures clients parse response correctly.
    end

    test "each key is valid for signature verification", %{conn: conn} do
      # REQUEST: Fetch JWKS
      conn = get(conn, ~p"/.well-known/jwks.json")
      %{"keys" => keys} = json_response(conn, 200)

      # VERIFY: Each key can be converted to JWK
      Enum.each(keys, fn key ->
        # Convert JWKS entry to JOSE.JWK
        jwk = JOSE.JWK.from(key)

        # Verify we can get the key type
        assert %JOSE.JWK{} = jwk

        # Verify it's the correct algorithm
        {_jwk_map, fields} = JOSE.JWK.to_map(jwk)
        assert fields["kty"] == "EC"
        assert fields["crv"] == "P-256"

        # LESSON: Published keys must be valid and usable for verification.
      end)
    end

    test "validates JWKS entries have all required fields", %{conn: conn} do
      # REQUEST
      conn = get(conn, ~p"/.well-known/jwks.json")
      %{"keys" => keys} = json_response(conn, 200)

      # VERIFY: Each key has all required fields
      Enum.each(keys, fn key ->
        assert JWKSPublisher.valid_jwks_entry?(key),
               "Key missing required fields: #{inspect(key)}"
      end)

      # LESSON: JWKS validation ensures compatibility with standard libraries.
    end
  end

  describe "JWKS format validation" do
    test "kid uniquely identifies each key", %{conn: conn} do
      # REQUEST
      conn = get(conn, ~p"/.well-known/jwks.json")
      %{"keys" => keys} = json_response(conn, 200)

      # VERIFY: All kids are unique
      kids = Enum.map(keys, & &1["kid"])
      assert length(kids) == length(Enum.uniq(kids))

      # LESSON: Unique kid allows clients to select the correct key
      # when verifying signatures, especially during key rotation.
    end

    test "x and y coordinates are Base64URL encoded", %{conn: conn} do
      # REQUEST
      conn = get(conn, ~p"/.well-known/jwks.json")
      %{"keys" => keys} = json_response(conn, 200)

      # VERIFY: x and y can be Base64URL decoded
      Enum.each(keys, fn key ->
        assert {:ok, _x_bytes} = Base.url_decode64(key["x"], padding: false)
        assert {:ok, _y_bytes} = Base.url_decode64(key["y"], padding: false)

        # LESSON: JWKS uses Base64URL encoding (not standard Base64) for coordinates.
      end)
    end

    test "crv specifies P-256 curve for ES256", %{conn: conn} do
      # REQUEST
      conn = get(conn, ~p"/.well-known/jwks.json")
      %{"keys" => keys} = json_response(conn, 200)

      # VERIFY: All ES256 keys use P-256 curve
      Enum.each(keys, fn key ->
        if key["alg"] == "ES256" do
          assert key["crv"] == "P-256"
        end

        # LESSON: ES256 algorithm uses the P-256 (secp256r1) curve.
        # Curve mismatch will cause verification failures.
      end)
    end
  end

  describe "error handling" do
    test "returns default key for unknown kid" do
      # NOTE: In this demo, unknown kids fall back to the default demo key.
      # In production with database-backed keys, you would handle missing
      # keys differently (skip them or return error).

      # Verify the publisher returns default key for unknown kid
      assert {:ok, jwks} = JWKSPublisher.get_jwks(["unknown-kid-12345"])
      assert %{"keys" => [key]} = jwks
      assert key["kid"] == "unknown-kid-12345"

      # LESSON: This demo uses a fallback strategy. In production, you might
      # want to skip unknown kids or return errors for better security.
    end
  end
end
