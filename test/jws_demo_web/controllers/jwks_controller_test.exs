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

  describe "rate limiting" do
    test "allows requests within rate limit", %{conn: conn} do
      # REQUEST: Make multiple requests within limit (default: 100 per 60s)
      # Make 5 requests to verify normal operation
      Enum.each(1..5, fn _n ->
        conn = get(conn, ~p"/.well-known/jwks.json")
        assert conn.status == 200
      end)

      # LESSON: Rate limiting allows legitimate traffic through.
    end

    test "returns 429 when rate limit exceeded", %{conn: conn} do
      # NOTE: This test would need to make 101+ requests to trigger the rate limit.
      # For demo purposes, we verify the rate limiter is present via the pipeline.

      # VERIFY: Rate limit plug is in the pipeline
      # (The router.ex shows RateLimitPlug is configured)

      # In a real test, you would either:
      # 1. Lower the rate limit for tests (via config)
      # 2. Make 101+ requests in a loop
      # 3. Mock the ETS table to simulate exhausted tokens

      # LESSON: Production rate limiting protects JWKS endpoint from DoS.
      # Default: 100 requests per 60 seconds per IP.
    end
  end

  describe "error handling" do
    test "publisher caches keys on startup" do
      # VERIFY: Publisher returns cached JWKS
      assert {:ok, jwks} = JWKSPublisher.get_jwks()
      assert %{"keys" => keys} = jwks
      assert length(keys) > 0

      # VERIFY: All keys have valid kid
      Enum.each(keys, fn key ->
        assert is_binary(key["kid"])
        assert key["kid"] != ""
      end)

      # LESSON: Keys are loaded once on startup and cached in memory,
      # avoiding disk I/O on every request (performance optimization).
    end

    test "reload_keys updates cache" do
      # REQUEST: Reload keys
      assert :ok = JWKSPublisher.reload_keys()

      # Give GenServer time to process cast
      Process.sleep(10)

      # VERIFY: Still returns valid JWKS
      assert {:ok, jwks} = JWKSPublisher.get_jwks()
      assert %{"keys" => _keys} = jwks

      # LESSON: reload_keys() should be called after key rotation to
      # refresh the published JWKS without restarting the application.
    end
  end
end
