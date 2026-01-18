# JWS Non-Repudiation Demo

**Phoenix 1.8 demonstration of JWS (JSON Web Signature) for non-repudiation in financial APIs.**

This project demonstrates cryptographic non-repudiation using ES256 (ECDSA P-256) signatures for
authorization requests. It serves as an educational reference implementation for
a [blog series on JWS](https://davidsulc.com/blog/jws-apis-intro).

## What This Demonstrates

### Core Features

#### Inbound Requests (Receiving from Partners)
- **JWS Signature Verification**: Comprehensive validation (algorithm, timestamps, integrity)
- **JWKS Caching**: Multi-tenant per-partner JWKS with stale-while-revalidate
- **Audit Trail**: "Forever proof" with re-verification support

#### Outbound Requests (Sending to Partners)
- **JWS Signing**: ES256 with flattened JSON + compact serialization
- **Client Library**: Simple API for signing and sending webhooks
- **JWKS Publishing**: Standard `/.well-known/jwks.json` endpoint

#### Bidirectional Non-Repudiation
- **Complete Audit Trail**: Both sides sign their requests
- **OpenSSL Verification**: Independent audit without our codebase
- **Educational Tests**: Demonstrates both inbound and outbound flows

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

## Quick Start

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

### Docker Quick Start

Prefer Docker? Run the entire stack with one command:

```bash
# Start PostgreSQL + Phoenix app
docker compose up

# Or run in background
docker compose up -d

# View logs
docker compose logs -f app

# Stop containers
docker compose down
```

Server runs at [http://localhost:4000](http://localhost:4000)

**Common Docker Commands:**

```bash
# Run tests (use 'run' with MIX_ENV=test to avoid port conflicts)
docker compose run --rm -e MIX_ENV=test app mix test

# Access IEx console
docker compose exec app iex -S mix

# Run migrations
docker compose exec app mix ecto.migrate

# Access PostgreSQL
docker compose exec postgres psql -U postgres -d jws_demo_dev

# Get a shell in the container
docker compose exec app sh

# View logs
docker compose logs -f app
```

**See [DOCKER.md](DOCKER.md) for complete Docker documentation**, including:
- Development vs production setup
- Running tests in containers
- Database backups
- Troubleshooting
- CI/CD integration
## Key Generation

Generate ES256 keypairs for testing:

```bash
# Generate new keypair
./scripts/generate_keys.sh

# Or manually with OpenSSL
openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -out public_key.pem
```

## Learning Path

Recommended order for understanding the codebase:

1. **Start with tests**: `test/jws_demo/jws/signer_test.exs`
2. **Core signing**: `lib/jws_demo/jws/signer.ex`
3. **Core verification**: `lib/jws_demo/jws/verifier.ex`
4. **Critical tests**: `test/jws_demo/jws/verifier_test.exs`
5. **Phoenix integration**: `lib/jws_demo_web/plugs/verify_jws_plug.ex`
6. **Audit trail**: `lib/jws_demo/jws/audit.ex`
7. **End-to-end flow**: `test/jws_demo/integration/authorization_flow_test.exs`
8. **OpenSSL verification**: `AUDIT.md`

## Demo Mode Configuration

**IMPORTANT:** This project runs in demo mode by default to simplify testing and education.

### What Demo Mode Does

The JWKS cache (`lib/jws_demo/jws/jwks_cache.ex`) has `@demo_mode true` configured, which:

- **Disables real HTTP requests** to partner JWKS endpoints (no external network calls)
- **Uses test fixtures** for key material inserted directly into ETS cache
- **Focuses on JWS verification logic** without HTTP/network complexity
- **Simplifies testing** - tests don't need mock HTTP servers

### Why Demo Mode Exists

Demo mode allows the codebase to demonstrate:
- Complete JWS verification logic
- Multi-tenant cache architecture
- Stale-while-revalidate patterns
- Error handling and fallbacks

Without requiring:
- Real partner JWKS endpoints
- Network connectivity in tests
- Mock HTTP servers
- External service dependencies

This makes the demo more accessible for learning while maintaining production-ready architecture.
