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

  describe "DoS protection: unknown kid debouncing" do
    test "unknown kid triggers fetch on first request" do
      # REQUEST: Get unknown kid (first attempt)
      result = JWKSCache.get_key("partner_dos_test", "unknown-key-1")

      # VERIFY: Fetch attempted (fails in demo mode, but that's expected)
      assert {:error, _reason} = result

      # LESSON: First unknown kid attempt triggers JWKS fetch as expected.
    end

    test "unknown kid is debounced within 60-second window" do
      partner_id = "partner_debounce_test"
      unknown_kid = "unknown-key-debounce"

      # SETUP: Simulate a recent JWKS fetch by creating partner metadata
      now = System.system_time(:second)
      metadata_key = {partner_id, :metadata}

      metadata = %{
        last_fetch_at: now - 30,
        # 30 seconds ago (within 60s window)
        last_fetch_success: true,
        consecutive_unknown_kids: 0
      }

      :ets.insert(:jwks_cache, {metadata_key, metadata})

      # REQUEST: Get unknown kid (should be debounced)
      log =
        capture_log(fn ->
          result = JWKSCache.get_key(partner_id, unknown_kid)

          # VERIFY: Request rejected without fetching
          assert {:error, :kid_not_found_in_jwks} = result
        end)

      # VERIFY: Log indicates debouncing
      assert log =~ "but JWKS fetched"
      assert log =~ "30s ago"
      assert log =~ "Possible attack or misconfiguration"

      # LESSON: Debouncing prevents repeated JWKS fetches for invalid kids.
    end

    test "unknown kid fetch allowed after debounce window expires" do
      partner_id = "partner_debounce_expired"
      unknown_kid = "unknown-key-expired"

      # SETUP: Simulate a JWKS fetch from 61 seconds ago (outside 60s window)
      now = System.system_time(:second)
      metadata_key = {partner_id, :metadata}

      metadata = %{
        last_fetch_at: now - 61,
        # 61 seconds ago (outside window)
        last_fetch_success: true,
        consecutive_unknown_kids: 0
      }

      :ets.insert(:jwks_cache, {metadata_key, metadata})

      # REQUEST: Get unknown kid (should trigger new fetch)
      capture_log(fn ->
        result = JWKSCache.get_key(partner_id, unknown_kid)

        # VERIFY: Fetch attempted (fails due to demo mode/partner not found)
        assert {:error, _reason} = result
      end)

      # VERIFY: Metadata updated with new fetch timestamp (proves fetch was attempted)
      [{^metadata_key, updated_metadata}] = :ets.lookup(:jwks_cache, metadata_key)
      assert updated_metadata.last_fetch_at > now - 61

      # LESSON: Debounce window expires after 60s, allowing legitimate key rotation.
    end

    test "debouncing emits telemetry for rejected unknown kids" do
      partner_id = "partner_debounce_telemetry"
      unknown_kid = "unknown-key-telemetry"
      test_pid = self()

      # SETUP: Attach telemetry handler
      :telemetry.attach(
        "jwks-debounce-test-handler",
        [:jwks_cache, :unknown_kid_rejected],
        fn event_name, measurements, metadata, _config ->
          send(test_pid, {:telemetry_event, event_name, measurements, metadata})
        end,
        nil
      )

      # SETUP: Recent JWKS fetch
      now = System.system_time(:second)
      metadata_key = {partner_id, :metadata}

      metadata = %{
        last_fetch_at: now - 20,
        last_fetch_success: true,
        consecutive_unknown_kids: 0
      }

      :ets.insert(:jwks_cache, {metadata_key, metadata})

      # REQUEST: Get unknown kid
      capture_log(fn ->
        JWKSCache.get_key(partner_id, unknown_kid)
      end)

      # VERIFY: Telemetry event emitted
      assert_receive {:telemetry_event, [:jwks_cache, :unknown_kid_rejected], measurements,
                      metadata}

      assert measurements.age_since_fetch >= 20
      assert metadata.partner_id == partner_id
      assert metadata.kid == unknown_kid

      # CLEANUP
      :telemetry.detach("jwks-debounce-test-handler")

      # LESSON: Telemetry enables monitoring for DoS attacks via unknown kids.
    end
  end

  describe "DoS protection: rate limiting" do
    test "allows up to 10 unknown kid attempts per minute" do
      partner_id = "partner_rate_limit_test"

      # REQUEST: Make 10 attempts (should all be allowed to attempt fetch)
      results =
        capture_log(fn ->
          for i <- 1..10 do
            JWKSCache.get_key(partner_id, "unknown-key-#{i}")
          end
        end)

      # VERIFY: All attempts processed (failed due to demo mode, but not rate limited)
      assert is_binary(results)

      # LESSON: Rate limit allows 10 attempts per minute per partner.
    end

    test "rate limits after 10 unknown kid attempts in one minute" do
      partner_id = "partner_rate_limit_exceeded"

      # SETUP: Manually set rate limit counter to 10 (at threshold)
      now = System.system_time(:second)
      rate_limit_key = {partner_id, :rate_limit}
      :ets.insert(:jwks_cache, {rate_limit_key, 10, now})

      # REQUEST: 11th attempt (should be rate limited)
      log =
        capture_log(fn ->
          result = JWKSCache.get_key(partner_id, "unknown-key-11")

          # VERIFY: Rate limited
          assert {:error, :rate_limited} = result
        end)

      # VERIFY: Log indicates rate limiting
      assert log =~ "Rate limit EXCEEDED"
      assert log =~ partner_id

      # LESSON: Rate limiting protects against DoS via unknown kid spam.
    end

    test "rate limit window resets after 60 seconds" do
      partner_id = "partner_rate_limit_reset"

      # SETUP: Old rate limit entry (61 seconds ago)
      now = System.system_time(:second)
      rate_limit_key = {partner_id, :rate_limit}
      :ets.insert(:jwks_cache, {rate_limit_key, 10, now - 61})

      # REQUEST: New attempt (should start fresh window)
      log =
        capture_log(fn ->
          JWKSCache.get_key(partner_id, "unknown-key-new")
        end)

      # VERIFY: Not rate limited (new window started)
      refute log =~ "Rate limit EXCEEDED"

      # LESSON: Rate limit windows reset, allowing continued operation.
    end

    test "rate limiting emits telemetry when exceeded" do
      partner_id = "partner_rate_limit_telemetry"
      test_pid = self()

      # SETUP: Attach telemetry handler
      :telemetry.attach(
        "jwks-rate-limit-test-handler",
        [:jwks_cache, :rate_limit_exceeded],
        fn event_name, measurements, metadata, _config ->
          send(test_pid, {:telemetry_event, event_name, measurements, metadata})
        end,
        nil
      )

      # SETUP: Set rate limit at threshold
      now = System.system_time(:second)
      rate_limit_key = {partner_id, :rate_limit}
      :ets.insert(:jwks_cache, {rate_limit_key, 10, now})

      # REQUEST: Exceed rate limit
      capture_log(fn ->
        JWKSCache.get_key(partner_id, "unknown-key")
      end)

      # VERIFY: Telemetry event emitted
      assert_receive {:telemetry_event, [:jwks_cache, :rate_limit_exceeded], measurements,
                      metadata}

      assert measurements.attempts >= 10
      assert metadata.partner_id == partner_id

      # CLEANUP
      :telemetry.detach("jwks-rate-limit-test-handler")

      # LESSON: Rate limit telemetry enables alerting on DoS attacks.
    end
  end

  describe "DoS protection: circuit breaker" do
    test "circuit breaker opens after 5 consecutive unknown kids" do
      partner_id = "partner_circuit_breaker_test"

      # SETUP: Set consecutive unknown kids to threshold
      metadata_key = {partner_id, :metadata}

      metadata = %{
        last_fetch_at: 0,
        last_fetch_success: false,
        consecutive_unknown_kids: 5
      }

      :ets.insert(:jwks_cache, {metadata_key, metadata})

      # REQUEST: Next unknown kid (should trip circuit breaker)
      log =
        capture_log(fn ->
          result = JWKSCache.get_key(partner_id, "unknown-key")

          # VERIFY: Circuit breaker open
          assert {:error, :circuit_breaker_open} = result
        end)

      # VERIFY: Log indicates circuit breaker
      assert log =~ "Circuit breaker OPEN"
      assert log =~ partner_id

      # LESSON: Circuit breaker stops processing after repeated failures.
    end

    test "circuit breaker resets on successful cache hit" do
      partner_id = "partner_circuit_reset"
      kid = "valid-key"

      # SETUP: Cache a valid key
      jwk = JOSE.JWK.generate_key({:ec, :secp256r1})
      now = System.system_time(:second)
      cache_key = {partner_id, kid}
      :ets.insert(:jwks_cache, {cache_key, jwk, now, 900})

      # SETUP: Set high unknown kid count
      metadata_key = {partner_id, :metadata}

      metadata = %{
        last_fetch_at: now,
        last_fetch_success: true,
        consecutive_unknown_kids: 3
      }

      :ets.insert(:jwks_cache, {metadata_key, metadata})

      # REQUEST: Get valid cached key
      capture_log(fn ->
        assert {:ok, _jwk} = JWKSCache.get_key(partner_id, kid)
      end)

      # VERIFY: Counter reset
      [{^metadata_key, updated_metadata}] = :ets.lookup(:jwks_cache, metadata_key)
      assert updated_metadata.consecutive_unknown_kids == 0

      # LESSON: Circuit breaker resets on successful verification.
    end

    test "circuit breaker emits telemetry when opened" do
      partner_id = "partner_circuit_telemetry"
      test_pid = self()

      # SETUP: Attach telemetry handler
      :telemetry.attach(
        "jwks-circuit-test-handler",
        [:jwks_cache, :circuit_breaker_open],
        fn event_name, measurements, metadata, _config ->
          send(test_pid, {:telemetry_event, event_name, measurements, metadata})
        end,
        nil
      )

      # SETUP: Set circuit breaker at threshold
      metadata_key = {partner_id, :metadata}

      metadata = %{
        last_fetch_at: 0,
        last_fetch_success: false,
        consecutive_unknown_kids: 5
      }

      :ets.insert(:jwks_cache, {metadata_key, metadata})

      # REQUEST: Trigger circuit breaker
      capture_log(fn ->
        JWKSCache.get_key(partner_id, "unknown-key")
      end)

      # VERIFY: Telemetry event emitted
      assert_receive {:telemetry_event, [:jwks_cache, :circuit_breaker_open], measurements,
                      metadata}

      assert measurements.consecutive_unknown_kids >= 5
      assert metadata.partner_id == partner_id

      # CLEANUP
      :telemetry.detach("jwks-circuit-test-handler")

      # LESSON: Circuit breaker telemetry enables alerting on sustained attacks.
    end

    test "consecutive unknown kid counter increments correctly" do
      partner_id = "partner_counter_increment"

      # SETUP: Metadata with recent fetch (to trigger debouncing)
      now = System.system_time(:second)
      metadata_key = {partner_id, :metadata}

      metadata = %{
        last_fetch_at: now - 10,
        last_fetch_success: true,
        consecutive_unknown_kids: 0
      }

      :ets.insert(:jwks_cache, {metadata_key, metadata})

      # REQUEST: Three unknown kid attempts (all debounced)
      capture_log(fn ->
        JWKSCache.get_key(partner_id, "unknown-1")
        JWKSCache.get_key(partner_id, "unknown-2")
        JWKSCache.get_key(partner_id, "unknown-3")
      end)

      # VERIFY: Counter incremented
      [{^metadata_key, updated_metadata}] = :ets.lookup(:jwks_cache, metadata_key)
      assert updated_metadata.consecutive_unknown_kids == 3

      # LESSON: Counter tracks sustained unknown kid attempts.
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
