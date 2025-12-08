# Build stage
FROM hexpm/elixir:1.18.0-erlang-27.2-alpine-3.21.0 AS build

# Install build dependencies
RUN apk add --no-cache build-base git openssl

# Set working directory
WORKDIR /app

# Install hex and rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Set build environment
ENV MIX_ENV=prod

# Copy dependency files
COPY mix.exs mix.lock ./

# Install dependencies
RUN mix deps.get --only prod && \
    mix deps.compile

# Copy application files
COPY config ./config
COPY lib ./lib
COPY priv ./priv

# Compile application
RUN mix compile

# Create release
RUN mix release

# Runtime stage
FROM alpine:3.21.0 AS app

# Install runtime dependencies
RUN apk add --no-cache \
    openssl \
    ncurses-libs \
    libstdc++ \
    libgcc

# Create app user
RUN addgroup -g 1000 app && \
    adduser -D -u 1000 -G app app

# Set working directory
WORKDIR /app

# Copy release from build stage
COPY --from=build --chown=app:app /app/_build/prod/rel/jws_demo ./

# Copy keys directory for demo
COPY --chown=app:app priv/keys ./priv/keys

# Switch to app user
USER app

# Expose port
EXPOSE 4000

# Set environment variables
ENV HOME=/app \
    MIX_ENV=prod \
    PORT=4000 \
    SECRET_KEY_BASE="CHANGE_ME_IN_PRODUCTION"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:4000/.well-known/jwks.json || exit 1

# Start the application
CMD ["bin/jws_demo", "start"]
