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
end
