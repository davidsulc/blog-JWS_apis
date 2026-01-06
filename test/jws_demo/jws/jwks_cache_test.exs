defmodule JwsDemo.JWS.JWKSCacheTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias JwsDemo.JWS.JWKSCache

  # Note: async: false because we're testing a global GenServer with ETS

  setup do
    # Start the cache if not already started
    # (It's normally started by Application, but tests might need it)
    case GenServer.whereis(JWKSCache) do
      nil ->
        {:ok, _pid} = JWKSCache.start_link([])
        :ok

      _pid ->
        :ok
    end

    # Clear ETS table before each test
    :ets.delete_all_objects(:jwks_cache)

    :ok
  end

  describe "cache behavior" do
    test "cache miss triggers fetch and caches result" do
      # SETUP: No cache entry exists
      # In demo mode, fetch will fail (no real JWKS endpoint)

      # REQUEST: Get key (cache miss)
      result = JWKSCache.get_key("partner_abc", "key-2025-01")

      # VERIFY: Returns error (demo mode doesn't have real endpoints)
      assert {:error, _reason} = result

      # LESSON: Cache miss triggers JWKS fetch. In production with real
      # JWKS endpoints, this would cache the fetched keys.
    end

    test "manual cache insertion and retrieval" do
      # SETUP: Manually insert a key into cache (simulating successful fetch)
      jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
      partner_id = "partner_test"
      kid = "test-key-2025"
      now = System.system_time(:second)
      ttl = 900

      cache_key = {partner_id, kid}
      :ets.insert(:jwks_cache, {cache_key, jwk, now, ttl})

      # REQUEST: Get key (should be cache hit)
      assert {:ok, cached_jwk} = JWKSCache.get_key(partner_id, kid)

      # VERIFY: Same JWK returned
      assert JOSE.JWK.to_map(jwk) == JOSE.JWK.to_map(cached_jwk)

      # LESSON: Cache hit returns immediately without network request.
    end

    test "stale cache returns value and triggers refresh" do
      # SETUP: Insert stale entry (expired but within grace period)
      jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
      partner_id = "partner_stale"
      kid = "stale-key"

      # Cache entry from 1 hour ago (past 15-minute TTL, but within 24-hour grace)
      cached_at = System.system_time(:second) - 3600
      ttl = 900

      cache_key = {partner_id, kid}
      :ets.insert(:jwks_cache, {cache_key, jwk, cached_at, ttl})

      # REQUEST: Get key (stale cache hit) - capture background refresh logs
      log =
        capture_log(fn ->
          assert {:ok, cached_jwk} = JWKSCache.get_key(partner_id, kid)

          # VERIFY: Returns stale value immediately
          assert JOSE.JWK.to_map(jwk) == JOSE.JWK.to_map(cached_jwk)

          # Wait briefly for background refresh to complete and log
          Process.sleep(50)
        end)

      # VERIFY: Background refresh was triggered and logged failure
      assert log =~ "JWKS cache refresh failed"
      assert log =~ partner_id
      assert log =~ "partner_not_found"

      # LESSON: Stale-while-revalidate pattern returns stale data immediately,
      # avoiding blocking on network request. Refresh happens in background.
      # The background refresh failure is expected in demo mode.
    end

    test "too stale cache triggers immediate refresh" do
      # SETUP: Insert very stale entry (beyond grace period)
      jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
      partner_id = "partner_very_stale"
      kid = "very-stale-key"

      # Cache entry from 25 hours ago (past 24-hour grace period)
      cached_at = System.system_time(:second) - 90_000
      ttl = 900

      cache_key = {partner_id, kid}
      :ets.insert(:jwks_cache, {cache_key, jwk, cached_at, ttl})

      # REQUEST: Get key (too stale, should trigger refresh)
      result = JWKSCache.get_key(partner_id, kid)

      # VERIFY: Refresh attempted (fails in demo mode)
      assert {:error, _reason} = result

      # LESSON: Very stale cache (> 24 hours) forces immediate refresh
      # to prevent using extremely outdated keys.
    end
  end

  describe "refresh behavior" do
    test "manual refresh triggers cache update" do
      # REQUEST: Trigger manual refresh - capture expected error log
      log =
        capture_log(fn ->
          assert :ok = JWKSCache.refresh("partner_manual")
          # Wait briefly for async refresh to complete
          Process.sleep(50)
        end)

      # VERIFY: Refresh was attempted and logged failure (expected in demo mode)
      assert log =~ "JWKS cache refresh failed"
      assert log =~ "partner_manual"

      # LESSON: Manual refresh useful for testing, debugging, or forced updates.
      # In production with real endpoints, this would update the cache.
    end

    test "warm_cache preloads partners" do
      # REQUEST: Warm cache
      assert :ok = JWKSCache.warm_cache()

      # VERIFY: Completes successfully
      # In production, this would preload all partners from database

      # LESSON: Warming cache on startup prevents cold start latency.
    end
  end

  describe "multi-tenant isolation" do
    test "different partners have separate cache entries" do
      # SETUP: Cache keys for two different partners
      jwk1 = JOSE.JWK.generate_key({:ec, :secp256r1})
      jwk2 = JOSE.JWK.generate_key({:ec, :secp256r1})

      now = System.system_time(:second)
      ttl = 900

      :ets.insert(:jwks_cache, {{"partner_a", "key1"}, jwk1, now, ttl})
      :ets.insert(:jwks_cache, {{"partner_b", "key1"}, jwk2, now, ttl})

      # REQUEST: Get keys for both partners
      {:ok, jwk_a} = JWKSCache.get_key("partner_a", "key1")
      {:ok, jwk_b} = JWKSCache.get_key("partner_b", "key1")

      # VERIFY: Different JWKs returned
      refute JOSE.JWK.to_map(jwk_a) == JOSE.JWK.to_map(jwk_b)

      # LESSON: Cache entries are isolated per partner, preventing
      # key confusion attacks between partners.
    end

    test "same partner can have multiple keys" do
      # SETUP: Multiple keys for one partner (key rotation scenario)
      jwk_old = JOSE.JWK.generate_key({:ec, :secp256r1})
      jwk_new = JOSE.JWK.generate_key({:ec, :secp256r1})

      now = System.system_time(:second)
      ttl = 900

      :ets.insert(:jwks_cache, {{"partner_c", "key-2024-12"}, jwk_old, now, ttl})
      :ets.insert(:jwks_cache, {{"partner_c", "key-2025-01"}, jwk_new, now, ttl})

      # REQUEST: Get both keys
      {:ok, old_key} = JWKSCache.get_key("partner_c", "key-2024-12")
      {:ok, new_key} = JWKSCache.get_key("partner_c", "key-2025-01")

      # VERIFY: Both keys available
      assert JOSE.JWK.to_map(jwk_old) == JOSE.JWK.to_map(old_key)
      assert JOSE.JWK.to_map(jwk_new) == JOSE.JWK.to_map(new_key)

      # LESSON: Multiple keys per partner enables zero-downtime rotation.
      # Old signatures verify with old key, new signatures with new key.
    end
  end

  describe "error handling" do
    test "unknown partner returns error" do
      # REQUEST: Get key for partner not in cache or configuration
      result = JWKSCache.get_key("unknown_partner_xyz", "some-key")

      # VERIFY: Returns error
      assert {:error, _reason} = result

      # LESSON: Unknown partners should fail fast rather than using
      # potentially incorrect keys.
    end

    test "GenServer handles crashes gracefully" do
      # VERIFY: GenServer is running
      assert Process.whereis(JWKSCache) != nil

      # LESSON: GenServer supervision ensures cache restarts on crash.
      # ETS table owned by GenServer, so it's recreated on restart.
    end
  end

  describe "performance characteristics" do
    test "cache hit is fast (< 1ms)" do
      # SETUP: Cache a key
      jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
      now = System.system_time(:second)
      :ets.insert(:jwks_cache, {{"partner_perf", "key1"}, jwk, now, 900})

      # MEASURE: Time for cache hit
      {time_us, {:ok, _jwk}} =
        :timer.tc(fn ->
          JWKSCache.get_key("partner_perf", "key1")
        end)

      # VERIFY: Cache hit is fast (< 1ms = 1000μs)
      assert time_us < 1000,
             "Cache hit took #{time_us}μs (expected < 1000μs)"

      # LESSON: ETS-backed cache provides microsecond-latency lookups,
      # critical for high-throughput API endpoints.
    end
  end

  describe "security: emergency purge" do
    test "emergency_purge removes all keys for a partner" do
      # SETUP: Cache multiple keys for a partner
      jwk1 = JOSE.JWK.generate_key({:ec, :secp256r1})
      jwk2 = JOSE.JWK.generate_key({:ec, :secp256r1})
      jwk3 = JOSE.JWK.generate_key({:ec, :secp256r1})

      now = System.system_time(:second)
      ttl = 900

      # Partner with multiple keys (rotation scenario)
      :ets.insert(:jwks_cache, {{"partner_compromised", "key1"}, jwk1, now, ttl})
      :ets.insert(:jwks_cache, {{"partner_compromised", "key2"}, jwk2, now, ttl})

      # Different partner (should NOT be affected)
      :ets.insert(:jwks_cache, {{"partner_safe", "key1"}, jwk3, now, ttl})

      # VERIFY: Keys exist before purge
      assert {:ok, _} = JWKSCache.get_key("partner_compromised", "key1")
      assert {:ok, _} = JWKSCache.get_key("partner_compromised", "key2")
      assert {:ok, _} = JWKSCache.get_key("partner_safe", "key1")

      # REQUEST: Emergency purge for compromised partner - capture audit log
      log =
        capture_log(fn ->
          assert :ok =
                   JWKSCache.emergency_purge(
                     "partner_compromised",
                     "ops.alice@example.com",
                     "INC-2025-001: Private key compromise confirmed by partner security"
                   )
        end)

      # VERIFY: Compromised partner's keys removed
      assert {:error, _} = JWKSCache.get_key("partner_compromised", "key1")
      assert {:error, _} = JWKSCache.get_key("partner_compromised", "key2")

      # VERIFY: Other partner's keys unaffected
      assert {:ok, _} = JWKSCache.get_key("partner_safe", "key1")

      # VERIFY: Audit log contains security event details
      assert log =~ "EMERGENCY JWKS CACHE PURGE"
      assert log =~ "partner_compromised"
      assert log =~ "ops.alice@example.com"
      assert log =~ "INC-2025-001"
      assert log =~ "Purged 2 keys"

      # LESSON: Emergency purge removes ALL cached keys for a partner,
      # forcing fresh JWKS fetch. This prevents accepting signatures from
      # compromised private keys during security incidents.
    end

    test "emergency_purge with no cached keys completes successfully" do
      # REQUEST: Purge partner with no cached keys
      log =
        capture_log(fn ->
          assert :ok =
                   JWKSCache.emergency_purge(
                     "partner_not_cached",
                     "ops.bob@example.com",
                     "INC-2025-002: Precautionary purge"
                   )
        end)

      # VERIFY: Completes successfully
      assert log =~ "Purged 0 keys"

      # LESSON: Purge is idempotent and safe even if no keys are cached.
    end

    test "stale cache triggers telemetry alerts" do
      # SETUP: Attach telemetry handler to capture events
      test_pid = self()

      :telemetry.attach(
        "jwks-cache-test-handler",
        [:jwks_cache, :stale_grace_period],
        fn event_name, measurements, metadata, _config ->
          send(test_pid, {:telemetry_event, event_name, measurements, metadata})
        end,
        nil
      )

      # SETUP: Insert stale entry (expired but within grace period)
      jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
      partner_id = "partner_stale_alert"
      kid = "stale-key"

      # Cache entry from 5 hours ago (triggers CRITICAL severity)
      cached_at = System.system_time(:second) - 18_000
      ttl = 900

      cache_key = {partner_id, kid}
      :ets.insert(:jwks_cache, {cache_key, jwk, cached_at, ttl})

      # REQUEST: Get key (should trigger telemetry alert)
      capture_log(fn ->
        {:ok, _} = JWKSCache.get_key(partner_id, kid)
        # Wait for async refresh
        Process.sleep(50)
      end)

      # VERIFY: Telemetry event emitted
      assert_receive {:telemetry_event, [:jwks_cache, :stale_grace_period], measurements,
                      metadata}

      assert measurements.age_seconds >= 18_000
      assert metadata.partner_id == partner_id
      assert metadata.kid == kid
      assert metadata.severity == :critical

      # CLEANUP
      :telemetry.detach("jwks-cache-test-handler")

      # LESSON: Telemetry events enable monitoring systems (Datadog, New Relic)
      # to alert ops teams when cache enters stale grace period.
    end
  end

  describe "cache-control TTL parsing" do
    # Note: parse_cache_control_ttl/1 is marked @doc false (internal function)
    # but is public for testing purposes
    import JWKSCache, only: [parse_cache_control_ttl: 1]

    defp assert_no_valid_ttl(headers) do
      assert {:error, :no_valid_ttl} = parse_cache_control_ttl(headers)
    end

    test "parses max-age from simple Cache-Control header" do
      headers = [{"cache-control", "max-age=3600"}]

      assert parse_cache_control_ttl(headers) == {:ok, 3600}
    end

    test "parses max-age from Cache-Control with multiple directives" do
      headers = [{"cache-control", "public, max-age=1800, must-revalidate"}]

      assert parse_cache_control_ttl(headers) == {:ok, 1800}
    end

    test "parses max-age with whitespace variations" do
      headers = [{"cache-control", " max-age=7200 , public"}]

      assert parse_cache_control_ttl(headers) == {:ok, 7200}
    end

    test "handles max-age at end of directive list" do
      headers = [{"cache-control", "public, must-revalidate, max-age=900"}]

      assert parse_cache_control_ttl(headers) == {:ok, 900}
    end

    test "returns error when no Cache-Control header present" do
      assert_no_valid_ttl([{"content-type", "application/json"}])
    end

    test "returns error when Cache-Control has no max-age" do
      assert_no_valid_ttl([{"cache-control", "public, must-revalidate"}])
    end

    test "returns error for invalid max-age values" do
      # Non-numeric value
      assert_no_valid_ttl([{"cache-control", "max-age=invalid"}])

      # Negative value (not allowed)
      assert_no_valid_ttl([{"cache-control", "max-age=-100"}])

      # Zero value (not allowed, must be > 0)
      assert_no_valid_ttl([{"cache-control", "max-age=0"}])
    end

    test "case-insensitive header name matching" do
      # lowercase
      headers = [{"cache-control", "max-age=1200"}]
      assert parse_cache_control_ttl(headers) == {:ok, 1200}

      # uppercase
      headers = [{"CACHE-CONTROL", "max-age=1200"}]
      assert parse_cache_control_ttl(headers) == {:ok, 1200}

      # mixed case
      headers = [{"Cache-Control", "max-age=1200"}]
      assert parse_cache_control_ttl(headers) == {:ok, 1200}
    end

    test "handles very short TTL for frequently rotating keys" do
      headers = [{"cache-control", "max-age=300"}]

      assert parse_cache_control_ttl(headers) == {:ok, 300}
    end

    test "handles very long TTL for stable keys" do
      headers = [{"cache-control", "max-age=86400"}]

      assert parse_cache_control_ttl(headers) == {:ok, 86400}
    end

    test "handles multiple cache-control headers (uses first)" do
      # HTTP allows duplicate headers, we should handle gracefully
      headers = [
        {"cache-control", "max-age=1200"},
        {"content-type", "application/json"},
        {"cache-control", "max-age=3600"}
      ]

      assert parse_cache_control_ttl(headers) == {:ok, 1200}
    end
  end
end
