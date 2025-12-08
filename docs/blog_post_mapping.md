# Blog Post to Code Mapping

This document maps each blog post in the 7-part JWS series to specific code locations in this demo project.

## Post 1: The Non-Repudiation Problem

**Core Concept**: Financial APIs need cryptographic proof of authorization.

### Code Locations

- **Architecture Overview**: See `README.md` → Project Structure
- **Complete Flow**: `test/jws_demo/integration/authorization_flow_test.exs:test "sign → verify → process → audit → re-verify"`
- **Database Schema**: `priv/repo/migrations/*`

### Key Concepts Demonstrated

- Multi-tenant partner management (`lib/jws_demo/partners/`)
- Audit trail storage (`lib/jws_demo/audit_logs/audit_log.ex`)
- End-to-end non-repudiation flow (integration tests)

---

## Post 2: Implementation with Elixir/JOSE

**Core Concept**: Signing and verifying JWS with ES256 using the JOSE library.

### Code Locations

**Signing:**
- `lib/jws_demo/jws/signer.ex:49` - `sign_flattened/3` function
- `lib/jws_demo/jws/signer.ex:122` - `sign_compact/3` function
- `test/jws_demo/jws/signer_test.exs:15` - Flattened JSON signing test

**Verifying:**
- `lib/jws_demo/jws/verifier.ex:68` - `verify/3` function
- `lib/jws_demo/jws/verifier.ex:85` - Validation pipeline
- `test/jws_demo/jws/verifier_test.exs:15` - Valid signature test

**Automatic Claims:**
- `lib/jws_demo/jws/signer.ex:151` - `enrich_payload/2` adds iat, exp, jti
- `test/jws_demo/jws/signer_test.exs:52` - Automatic claims test

**Serialization Formats:**
- `lib/jws_demo/jws/signer.ex:87` - Flattened JSON creation
- `lib/jws_demo/jws/signer.ex:139` - Compact format creation
- `lib/jws_demo/jws/verifier.ex:76` - Support both formats

### Key Concepts Demonstrated

- Flattened JSON vs Compact serialization
- Automatic timestamp and UUID generation
- Canonical JSON encoding (`Jason.encode!(payload, pretty: false)`)
- JOSE library integration

---

## Post 3: Algorithm Security

**Core Concept**: Preventing algorithm confusion and 'none' algorithm attacks.

### Code Locations

**Algorithm Whitelist:**
- `lib/jws_demo/jws/verifier.ex:64` - Default allowed algorithms
- `lib/jws_demo/jws/verifier.ex:103` - `check_algorithm/2` enforcement
- `test/jws_demo/jws/verifier_test.exs:98` - 'none' algorithm test
- `test/jws_demo/jws/verifier_test.exs:116` - Algorithm not in whitelist test

**Crypto-Level Enforcement:**
- `lib/jws_demo/jws/verifier.ex:117` - `JOSE.JWS.verify_strict/3` with algorithm list
- Prevents downgrade attacks at cryptographic level

### Key Concepts Demonstrated

- Algorithm whitelist enforcement (only ES256)
- Defense against 'none' algorithm attack
- Defense against algorithm confusion attack
- Double-check: application-level + crypto-level validation

---

## Post 4: JWKS Key Distribution

**Core Concept**: Publishing and caching public keys for multi-tenant systems.

### Code Locations

**JWKS Publishing:**
- `lib/jws_demo/jws/jwks_publisher.ex:47` - `get_jwks/1` function
- `lib/jws_demo_web/controllers/jwks_controller.ex:68` - JWKS endpoint
- `lib/jws_demo_web/router.ex:17` - `/.well-known/jwks.json` route
- `test/jws_demo_web/controllers/jwks_controller_test.exs:13` - JWKS format test

**JWKS Caching:**
- `lib/jws_demo/jws/jwks_cache.ex:67` - `get_key/2` with caching logic
- `lib/jws_demo/jws/jwks_cache.ex:153` - Cache hit/miss handling
- `lib/jws_demo/jws/jwks_cache.ex:212` - Stale-while-revalidate strategy
- `test/jws_demo/jws/jwks_cache_test.exs:31` - Cache hit test
- `test/jws_demo/jws/jwks_cache_test.exs:54` - Stale cache test

**Key Rotation:**
- `lib/jws_demo/jws/jwks_cache.ex:166` - Stale cache with background refresh
- Multiple keys per partner support

### Key Concepts Demonstrated

- Standard JWKS format (RFC 7517)
- Cache-Control headers (`max-age=600, must-revalidate`)
- Per-partner JWKS with 15-minute TTL
- Stale-while-revalidate (24-hour grace period)
- Zero-downtime key rotation support
- Performance: 100μs cache hit vs 50-200ms fetch

---

## Post 5: Audit Trails and Re-Verification

**Core Concept**: "Forever proof" by storing original JWS + partner key snapshots.

### Code Locations

**Audit Logging:**
- `lib/jws_demo/jws/audit.ex:91` - `log_authorization/3` function
- Database schema: `priv/repo/migrations/20251207202434_create_audit_logs.exs`
- `test/jws_demo/jws/audit_test.exs:14` - Audit storage test

**Re-Verification:**
- `lib/jws_demo/jws/audit.ex:143` - `re_verify/1` function
- `test/jws_demo/jws/audit_test.exs:82` - Re-verification test
- `test/jws_demo/jws/audit_test.exs:120` - Tamper detection test

**OpenSSL Verification Package:**
- `lib/jws_demo/jws/audit.ex:186` - `generate_verification_package/2`
- `AUDIT.md` - Complete OpenSSL verification protocol
- `scripts/convert_signature_to_der.exs` - Signature format conversion
- `test/jws_demo/jws/audit_test.exs:154` - Package generation test

**Critical Design Decisions:**
- `lib/jws_demo/audit_logs/audit_log.ex:13` - Store original JWS (TEXT field)
- `lib/jws_demo/audit_logs/audit_log.ex:14` - Store partner key snapshot (JSONB)
- Why: JSON canonicalization issues + key rotation

### Key Concepts Demonstrated

- Never reconstruct JWS from payload (JSON formatting issues)
- Store partner key snapshot (enables re-verification after rotation)
- Independent verification without our codebase (OpenSSL)
- Tamper detection in audit trail
- Verification package for disputes/audits

---

## Post 6: Beyond Authentication

**Core Concept**: JWS for authorization (not authentication). Simplified architecture.

### Code Locations

**JWS-Only Architecture:**
- `lib/jws_demo_web/plugs/verify_jws_plug.ex:71` - Extract partner_id from header
- Demo simplification: X-Partner-ID header (production would use mTLS)
- No OAuth/OIDC complexity for this use case

**Authorization vs Authentication:**
- `lib/jws_demo_web/controllers/authorization_controller.ex:73` - Process authorization
- Partner already authenticated (via mTLS in production)
- JWS proves authorization intent, not identity

### Key Concepts Demonstrated

- JWS for authorization (not authentication)
- Simplified partner identification (header vs mTLS)
- Single-purpose API (no complex auth flows)
- Clear separation of concerns

---

## Post 7: Critical Test Cases

**Core Concept**: Comprehensive test suite covering all security scenarios.

### Code Locations

**11 Critical Tests (from blog post):**

1. ✅ `test/jws_demo/jws/verifier_test.exs:15` - Valid signature acceptance
2. ✅ `test/jws_demo/jws/verifier_test.exs:206` - Expired token rejection
3. ✅ `test/jws_demo/jws/verifier_test.exs:132` - Tampered payload rejection
4. ✅ `test/jws_demo/jws/verifier_test.exs:151` - Wrong key rejection
5. ✅ `test/jws_demo/jws/verifier_test.exs:98` - 'none' algorithm rejection
6. ✅ `test/jws_demo/jws/verifier_test.exs:116` - Algorithm not in whitelist
7. ✅ `test/jws_demo/jws/verifier_test.exs:49` - 2-minute clock skew acceptance
8. ✅ `test/jws_demo/jws/verifier_test.exs:234` - 7-minute clock skew rejection
9. ✅ `test/jws_demo/jws/verifier_test.exs:170` - Unknown kid rejection
10. ✅ `test/jws_demo/jws/verifier_test.exs:262` - JSON whitespace sensitivity
11. ✅ `test/jws_demo/jws/verifier_test.exs:282` - Verification with original JWS

**Additional Test Categories:**

- **Signer Tests**: `test/jws_demo/jws/signer_test.exs` (4 tests)
- **Plug Tests**: `test/jws_demo_web/plugs/verify_jws_plug_test.exs` (9 tests)
- **Controller Tests**: `test/jws_demo_web/controllers/authorization_controller_test.exs` (9 tests)
- **Audit Tests**: `test/jws_demo/jws/audit_test.exs` (8 tests)
- **Cache Tests**: `test/jws_demo/jws/jwks_cache_test.exs` (11 tests)
- **Integration Tests**: `test/jws_demo/integration/authorization_flow_test.exs` (6 tests)

### Key Concepts Demonstrated

- Security attack prevention (algorithm, tampering, replay)
- Clock skew handling (5-minute tolerance)
- JSON canonicalization awareness
- Comprehensive error scenarios
- Performance characteristics (<10ms verification)

---

## Complete Flow Example

**File**: `test/jws_demo/integration/authorization_flow_test.exs:32`

This single test demonstrates the entire blog series:

1. **Signing** (Post 2): Partner creates JWS signature
2. **Verification** (Posts 2, 3, 7): Server verifies with comprehensive checks
3. **Authorization** (Post 6): Process authorization request
4. **Audit** (Post 5): Store in audit trail with original JWS
5. **Re-Verification** (Post 5): Prove authorization months later
6. **OpenSSL Package** (Post 5): Independent verification

See the test output for step-by-step execution with educational commentary.

---

## Quick Reference

### By Blog Post

| Post | Primary Files | Test Files |
|------|--------------|------------|
| Post 1 | Architecture overview | `test/jws_demo/integration/authorization_flow_test.exs` |
| Post 2 | `signer.ex`, `verifier.ex` | `signer_test.exs`, `verifier_test.exs` |
| Post 3 | `verifier.ex:103` | `verifier_test.exs:98-116` |
| Post 4 | `jwks_publisher.ex`, `jwks_cache.ex` | `jwks_controller_test.exs`, `jwks_cache_test.exs` |
| Post 5 | `audit.ex`, `AUDIT.md` | `audit_test.exs` |
| Post 6 | `verify_jws_plug.ex`, architecture | All integration tests |
| Post 7 | All test files | 75+ tests total |

### By Security Feature

| Feature | Code Location | Test Location |
|---------|--------------|---------------|
| Algorithm whitelist | `verifier.ex:103` | `verifier_test.exs:98-116` |
| Timestamp validation | `verifier.ex:186` | `verifier_test.exs:206-258` |
| Clock skew tolerance | `verifier.ex:64` | `verifier_test.exs:49-69` |
| Tamper detection | `verifier.ex:117` | `verifier_test.exs:132-148` |
| JSON canonicalization | `signer.ex:84` | `verifier_test.exs:262-298` |
| JWKS caching | `jwks_cache.ex:67` | `jwks_cache_test.exs:31-95` |
| Audit trail | `audit.ex:91-143` | `audit_test.exs:14-163` |
| OpenSSL verification | `AUDIT.md` | `audit_test.exs:154-260` |

### By Use Case

| Use Case | Start Here |
|----------|-----------|
| Sign a payload | `lib/jws_demo/jws/signer.ex:49` |
| Verify a signature | `lib/jws_demo/jws/verifier.ex:68` |
| Publish JWKS | `lib/jws_demo_web/controllers/jwks_controller.ex` |
| Cache JWKS | `lib/jws_demo/jws/jwks_cache.ex:67` |
| Store in audit | `lib/jws_demo/jws/audit.ex:91` |
| Re-verify later | `lib/jws_demo/jws/audit.ex:143` |
| OpenSSL verify | `AUDIT.md` |
| Full integration | `test/jws_demo/integration/authorization_flow_test.exs:32` |

---

**Last Updated**: 2025-12-07
**Version**: 1.0
