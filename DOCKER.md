# Docker Deployment Guide

This guide explains how to run the JWS Demo project using Docker and Docker Compose.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+

## Quick Start (Development)

The easiest way to run the project is using Docker Compose:

```bash
# Start both PostgreSQL and the Phoenix app
docker compose up

# Or run in detached mode
docker compose up -d

# View logs
docker compose logs -f app

# Stop containers
docker compose down

# Stop and remove volumes (clean slate)
docker compose down -v
```

The application will be available at http://localhost:4000

## Architecture

The Docker setup includes two services:

1. **postgres** - PostgreSQL 16 database
2. **app** - Phoenix application

### Development Setup (`docker-compose.yml`)

- Uses `Dockerfile.dev` for faster rebuilds
- Mounts source code for hot reloading
- Automatically runs migrations and seeds
- Exposes PostgreSQL port 5432 for local access

### Production Setup (`docker-compose.prod.yml`)

- Uses production `Dockerfile` with Elixir releases
- No source code mounting (release artifact)
- Requires environment variables via `.env` file
- Production-ready configuration

## Development Workflow

### Starting the Application

```bash
# Build and start
docker compose up --build

# The app will:
# 1. Wait for PostgreSQL to be ready
# 2. Create the database (if needed)
# 3. Run migrations
# 4. Seed test data
# 5. Start Phoenix server
```

### Running Commands Inside Containers

Use `docker compose exec` to run commands in running containers:

```bash
# Run mix commands
docker compose exec app mix test
docker compose exec app mix compile
docker compose exec app mix deps.get

# Access interactive IEx console
docker compose exec app iex -S mix

# Run database commands
docker compose exec app mix ecto.migrate
docker compose exec app mix ecto.rollback
docker compose exec app mix ecto.reset
docker compose exec app mix run priv/repo/seeds.exs

# Access PostgreSQL directly
docker compose exec postgres psql -U postgres -d jws_demo_dev

# Generate keys
docker compose exec app sh scripts/generate_keys.sh

# Check Phoenix routes
docker compose exec app mix phx.routes

# Run specific tests
docker compose exec app mix test test/jws_demo/jws/signer_test.exs
docker compose exec app mix test --only integration

# Get a shell in the container
docker compose exec app sh

# Run as root (if needed)
docker compose exec --user root app sh
```

**Alternative syntax** (if you prefer `docker` over `docker compose`):

```bash
# Same commands, different syntax
docker exec jws_demo_app mix test
docker exec -it jws_demo_app iex -S mix
docker exec -it jws_demo_postgres psql -U postgres
```

**Running one-off commands** (without starting full stack):

```bash
# Run command in new container
docker compose run --rm app mix test
docker compose run --rm app mix ecto.migrate
```

**Difference:**
- `docker compose exec` - Execute in **running** container (faster)
- `docker compose run` - Create **new** container for command (isolated)

### Rebuilding After Changes

```bash
# Rebuild after dependency changes
docker compose up --build

# Or rebuild specific service
docker compose build app
```

## Production Deployment

### 1. Create Environment File

```bash
cp .env.example .env
```

Edit `.env` with production values:

```bash
# Required variables
POSTGRES_PASSWORD=your_secure_password
SECRET_KEY_BASE=$(docker compose run --rm app mix phx.gen.secret)
PHX_HOST=your-domain.com

# Optional
POSTGRES_USER=postgres
POSTGRES_DB=jws_demo_prod
APP_PORT=4000
POOL_SIZE=10
JWKS_DEMO_MODE=false
```

### 2. Deploy with Production Compose

```bash
# Start production stack
docker compose -f docker-compose.prod.yml up -d

# Check logs
docker compose -f docker-compose.prod.yml logs -f

# View status
docker compose -f docker-compose.prod.yml ps
```

### 3. Run Production Migrations

```bash
# Run migrations
docker compose -f docker-compose.prod.yml exec app bin/jws_demo eval "JwsDemo.Release.migrate()"

# Seed data (optional)
docker compose -f docker-compose.prod.yml exec app bin/jws_demo eval "JwsDemo.Release.seed()"
```

**Note:** You'll need to create `lib/jws_demo/release.ex` with migration helpers for production. See Phoenix release documentation.

## Dockerfile Details

### Development Dockerfile (`Dockerfile.dev`)

```dockerfile
FROM hexpm/elixir:1.18.0-erlang-27.2-alpine-3.21.0

# Fast rebuilds with layer caching
# Source code mounted as volume
# Mix dependencies persisted
```

**Optimized for:**
- Fast rebuild times
- Hot code reloading
- Interactive development

### Production Dockerfile (`Dockerfile`)

```dockerfile
# Multi-stage build
# Build stage: Compile application
# Runtime stage: Minimal Alpine image with release

# Results in ~50MB final image
```

**Optimized for:**
- Small image size
- Security (minimal dependencies)
- Fast startup
- Production performance

## Health Checks

Both containers include health checks:

### PostgreSQL
```bash
pg_isready -U postgres
```
Checks every 10 seconds

### Phoenix App
```bash
wget http://localhost:4000/.well-known/jwks.json
```
Checks every 30 seconds after 30-second startup period

## Volumes

### Development
- `postgres_data` - Database persistence
- `build` - Compiled Elixir code (faster rebuilds)
- `deps` - Mix dependencies (faster rebuilds)
- `.` (mounted) - Source code hot reload

### Production
- `postgres_data` - Database persistence only

## Networking

Custom bridge network `jws_demo_network` allows:
- Service discovery (app → postgres by hostname)
- Isolation from other Docker networks
- Custom DNS resolution

## Port Mapping

| Service | Internal Port | Host Port | Configurable |
|---------|--------------|-----------|--------------|
| PostgreSQL | 5432 | 5433 | Yes (POSTGRES_PORT) |
| Phoenix App | 4000 | 4000 | Yes (APP_PORT) |

**Note:** PostgreSQL uses host port **5433** instead of the default 5432 to avoid conflicts with local PostgreSQL installations.

The app container connects to PostgreSQL using the internal container port (5432) via Docker's internal network. The host port (5433) is only needed if you want to connect from your local machine using tools like `psql`.

## Troubleshooting

### Port Already in Use

**Error:** `Bind for 0.0.0.0:5432 failed: port is already allocated`

This means you have PostgreSQL (or another service) already running on port 5432.

**Solution:** The compose files now use port 5433 by default. If you still get conflicts:

```bash
# Check what's using the port
sudo lsof -i :5433
# or
sudo netstat -tulpn | grep 5433

# Option 1: Change to a different port
# Edit docker-compose.yml and change "5433:5432" to "5434:5432"

# Option 2: Stop your local PostgreSQL (if not needed)
sudo systemctl stop postgresql
# or on macOS
brew services stop postgresql
```

### Database Connection Issues

```bash
# Check PostgreSQL health
docker compose ps postgres

# View PostgreSQL logs
docker compose logs postgres

# Test connection manually
docker compose exec postgres psql -U postgres -d jws_demo_dev
```

### Application Won't Start

```bash
# View detailed logs
docker compose logs -f app

# Check if migrations ran
docker compose exec app mix ecto.migrations

# Manually run migrations
docker compose exec app mix ecto.migrate
```

### Rebuild From Scratch

```bash
# Stop and remove everything
docker compose down -v

# Remove images
docker compose down --rmi all

# Rebuild
docker compose build --no-cache
docker compose up
```

### Performance Issues

Development mounts can be slow on macOS/Windows. Options:

1. **Use named volumes for source**:
   - Faster but no hot reload

2. **Enable file sharing performance**:
   - Docker Desktop → Settings → Resources → File Sharing

3. **Run natively**:
   - Use Docker only for PostgreSQL

## Security Considerations

### Development

- Default credentials (postgres/postgres)
- Debug tools enabled
- Source code exposed
- **Never use in production**

### Production

- Use strong passwords (.env file)
- SECRET_KEY_BASE must be unique
- Don't commit .env to version control
- Use Docker secrets for sensitive data
- Enable SSL (see AUDIT.md)

## Monitoring

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f app

# Last 100 lines
docker compose logs --tail=100 app
```

### Check Resource Usage

```bash
docker stats jws_demo_app jws_demo_postgres
```

### LiveDashboard

Access Phoenix LiveDashboard at:
- Development: http://localhost:4000/dev/dashboard
- Production: Configure authentication (see README.md)

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Docker Build

on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build and test
        run: |
          docker compose build
          docker compose run app mix test
```

## Backup and Restore

### Backup Database

```bash
docker compose exec postgres pg_dump -U postgres jws_demo_dev > backup.sql
```

### Restore Database

```bash
cat backup.sql | docker compose exec -T postgres psql -U postgres -d jws_demo_dev
```

## References

- [Dockerfile Reference](https://docs.docker.com/engine/reference/builder/)
- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Phoenix Deployment Guides](https://hexdocs.pm/phoenix/deployment.html)
- [Elixir Releases](https://hexdocs.pm/mix/Mix.Tasks.Release.html)

---

**Questions?** See the main [README.md](README.md) or open an issue.
