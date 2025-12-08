# JWS Non-Repudiation Demo

**Phoenix 1.8 demonstration of JWS (JSON Web Signature) for non-repudiation in financial APIs.**

This project demonstrates cryptographic non-repudiation using ES256 (ECDSA P-256) signatures for authorization requests. It serves as an educational reference implementation for the 7-part blog series on JWS security.

## 📚 Blog Series

This codebase implements concepts from:

1. **Post 1**: The Non-Repudiation Problem → Architecture overview
2. **Post 2**: Implementation with Elixir/JOSE → Signer + Verifier modules
3. **Post 3**: Algorithm Security → Whitelist enforcement
4. **Post 4**: JWKS Key Distribution → Publisher + Cache
5. **Post 5**: Audit Trails → Re-verification + OpenSSL packages
6. **Post 6**: Beyond Authentication → JWS-only (no mTLS/OAuth)
7. **Post 7**: Critical Test Cases → Comprehensive test suite

See [docs/blog_post_mapping.md](docs/blog_post_mapping.md) for detailed code-to-post mapping.

## 🎯 What This Demonstrates

### Core Features

- ✅ **JWS Signing**: ES256 with flattened JSON + compact serialization
- ✅ **Signature Verification**: Comprehensive validation (algorithm, timestamps, integrity)
- ✅ **JWKS Publishing**: Standard `/.well-known/jwks.json` endpoint
- ✅ **Multi-Tenant Caching**: Per-partner JWKS with stale-while-revalidate
- ✅ **Audit Trail**: "Forever proof" with re-verification support
- ✅ **OpenSSL Verification**: Independent audit without our codebase

### Security Validations

- Algorithm whitelist (prevents 'none' algorithm attack)
- Timestamp validation with clock skew tolerance (5 minutes)
- Cryptographic integrity checks
- Tamper detection in audit trail
- JSON canonicalization awareness

### Performance

- Cache hit: ~100μs (ETS lookup)
- Signature verification: <10ms
- 100-2000x improvement with caching

## 🚀 Quick Start

### Prerequisites

- Elixir 1.14+ and Erlang/OTP 25+
- PostgreSQL 14+
- OpenSSL 1.1.1+ (for audit verification)

### Setup

```bash
# Clone the repository
cd /home/david/obsidian/main/blog/jws/code/jws_demo

# Install dependencies
mix deps.get

# Create database
mix ecto.create

# Run migrations
mix ecto.migrate

# Seed test data
mix run priv/repo/seeds.exs

# Run tests
mix test

# Start server
mix phx.server
```

Server runs at [http://localhost:4000](http://localhost:4000)

## 📡 API Endpoints

### JWKS Endpoint

```bash
GET /.well-known/jwks.json
```

Publishes public keys for partners to verify our signatures.

**Response:**
```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "kid": "demo-2025-01",
      "alg": "ES256",
      "crv": "P-256",
      "x": "gfCoE4Yhm3NL...",
      "y": "C86t3ZhtQ1RL..."
    }
  ]
}
```

**Cache headers:** `Cache-Control: public, max-age=600, must-revalidate`

### Authorization Endpoint

```bash
POST /api/v1/authorizations
Content-Type: application/json
X-Partner-ID: partner_abc

{
  "payload": "eyJhbW91bnQ...",
  "protected": "eyJhbGciOiJF...",
  "signature": "MEUCIQD..."
}
```

Accepts JWS-signed authorization requests.

**Response (success):**
```json
{
  "status": "approved",
  "instruction_id": "txn_123",
  "amount": 50000,
  "currency": "EUR",
  "verified_at": "2025-12-07T20:50:49Z",
  "jti": "668a741c-ae0e-43fa-90fc-f3ecbf0ee3f9"
}
```

**Response (error):**
```json
{
  "error": "verification_failed",
  "message": "JWS signature verification failed",
  "partner_id": "partner_abc"
}
```

## 🧪 Testing

### Run All Tests

```bash
mix test
```

### Run Specific Test Suites

```bash
# Core JWS functionality
mix test test/jws_demo/jws/

# Phoenix integration
mix test test/jws_demo_web/

# End-to-end integration
mix test test/jws_demo/integration/
```

### Test Coverage

- **75+ tests** across 9 test files
- **14 critical test cases** from Blog Post 7
- **Integration tests** demonstrating complete flow
- **Performance tests** validating sub-10ms verification

## 📂 Project Structure

```
lib/
├── jws_demo/
│   ├── jws/
│   │   ├── signer.ex              # ES256 signing (Post 2)
│   │   ├── verifier.ex            # Comprehensive validation (Post 2, 7)
│   │   ├── jwks_cache.ex          # Multi-tenant caching (Post 4)
│   │   ├── jwks_publisher.ex      # JWKS endpoint logic
│   │   └── audit.ex               # Audit trail + re-verification (Post 5)
│   ├── partners/
│   │   ├── partner.ex             # Partner schema
│   │   └── partner_config.ex      # JWKS configuration
│   └── audit_logs/
│       └── audit_log.ex           # Audit log schema
└── jws_demo_web/
    ├── controllers/
    │   ├── jwks_controller.ex     # GET /.well-known/jwks.json
    │   └── authorization_controller.ex  # POST /api/v1/authorizations
    └── plugs/
        └── verify_jws_plug.ex     # JWS verification in pipeline

test/
├── jws_demo/jws/                  # Core JWS tests
├── jws_demo_web/                  # Phoenix integration tests
└── integration/                    # End-to-end tests

priv/
├── keys/                           # Test keypairs (ES256)
└── repo/
    ├── migrations/                 # Database schema
    └── seeds.exs                   # Test partner data

scripts/
├── generate_keys.sh                # Generate ES256 keypairs
└── convert_signature_to_der.exs    # For OpenSSL verification

docs/
└── blog_post_mapping.md            # Code-to-blog-post mapping
```

## 🔐 Key Generation

Generate ES256 keypairs for testing:

```bash
# Generate new keypair
./scripts/generate_keys.sh

# Or manually with OpenSSL
openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
```

## 🔍 Audit & Verification

### Generate Verification Package

```elixir
# In IEx
iex> JwsDemo.JWS.Audit.generate_verification_package("txn_123", "/tmp/audit_pkg")
:ok
```

Creates package with:
- `jws_original.txt` - Original JWS signature
- `public_key.pem` - Partner public key (PEM)
- `public_key.jwk` - Partner public key (JWK)
- `payload_decoded.json` - Human-readable payload
- `VERIFICATION.md` - Step-by-step instructions

### Verify with OpenSSL

See [AUDIT.md](AUDIT.md) for complete protocol.

Quick version:

```bash
cd /tmp/audit_pkg

# Extract JWS parts
JWS=$(cat jws_original.txt)
HEADER=$(echo "$JWS" | cut -d'.' -f1)
PAYLOAD=$(echo "$JWS" | cut -d'.' -f2)
SIGNATURE=$(echo "$JWS" | cut -d'.' -f3)

# Create signing input
echo -n "${HEADER}.${PAYLOAD}" > signing_input.txt

# Convert signature to DER
mix run scripts/convert_signature_to_der.exs "$SIGNATURE" > signature.der

# Verify
openssl dgst -sha256 -verify public_key.pem -signature signature.der signing_input.txt
# Output: Verified OK
```

## 🗄️ Database

### Schema

- **partners**: Partner organizations
- **partner_configs**: JWKS URLs and settings per partner
- **audit_logs**: Signed authorizations with original JWS + key snapshots

### Seed Data

```bash
mix run priv/repo/seeds.exs
```

Creates 4 test partners:
- `partner_abc` - ABC Financial Institution (active)
- `partner_xyz` - XYZ Payment Processor (active)
- `partner_demo` - Demo Partner Inc (active, localhost JWKS)
- `partner_inactive` - Inactive Partner LLC (inactive)

## 📖 Educational Features

### Inline Comments

Every module includes educational comments explaining:
- **What** the code does
- **Why** specific design decisions were made
- **How** it relates to blog post concepts

### Test Documentation

Tests include LESSON comments demonstrating:
- Security principles
- Attack prevention
- Non-repudiation guarantees

Example:
```elixir
# LESSON: This proves the signature validates correctly and
# the payload is intact. This is the foundation of non-repudiation.
```

### Blog Post Mapping

See [docs/blog_post_mapping.md](docs/blog_post_mapping.md) for mapping between code and blog concepts.

## 🎓 Learning Path

Recommended order for understanding the codebase:

1. **Start with tests**: `test/jws_demo/jws/signer_test.exs`
2. **Core signing**: `lib/jws_demo/jws/signer.ex`
3. **Core verification**: `lib/jws_demo/jws/verifier.ex`
4. **Critical tests**: `test/jws_demo/jws/verifier_test.exs`
5. **Phoenix integration**: `lib/jws_demo_web/plugs/verify_jws_plug.ex`
6. **Audit trail**: `lib/jws_demo/jws/audit.ex`
7. **End-to-end flow**: `test/jws_demo/integration/authorization_flow_test.exs`
8. **OpenSSL verification**: `AUDIT.md`

## ⚠️ Production Considerations

This is a **demonstration project**. For production use:

### Security

- ✅ Use proper key management (HSM, KMS)
- ✅ Implement mTLS for partner authentication
- ✅ Add rate limiting and DDoS protection
- ✅ Rotate keys regularly (every 90 days)
- ✅ Monitor for algorithm downgrade attacks
- ✅ Implement proper JWKS fetching (not demo mode)

### Performance

- ✅ Add Redis for distributed JWKS cache
- ✅ Implement proper connection pooling
- ✅ Add CDN for JWKS endpoint
- ✅ Monitor verification latency
- ✅ Implement circuit breakers for JWKS fetch

### Compliance

- ✅ Enable audit log retention policies
- ✅ Implement proper access controls
- ✅ Add encryption at rest for sensitive data
- ✅ Ensure GDPR/PCI compliance
- ✅ Regular security audits

## 🔗 References

### RFCs

- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) - JSON Web Signature (JWS)
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) - JSON Web Key (JWK)
- [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) - JSON Web Algorithms (JWA)
- [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) - OAuth 2.0 Authorization Server Metadata

### Libraries

- [JOSE](https://hexdocs.pm/jose) - JSON Object Signing and Encryption
- [Phoenix](https://www.phoenixframework.org/) - Web framework
- [Ecto](https://hexdocs.pm/ecto) - Database wrapper

### Standards

- PSD2 RTS (Strong Customer Authentication)
- PCI DSS (Payment Card Industry Data Security Standard)
- OpenID Connect Core 1.0

## 📝 License

Educational demonstration project.

## 🤝 Contributing

This is a reference implementation for educational purposes. Feedback welcome!

---

**Built with**: Elixir 1.18, Phoenix 1.8, PostgreSQL 16
**Last Updated**: 2025-12-07
**Maintained by**: JWS Demo Project
