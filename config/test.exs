import Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
config :jws_demo, JwsDemo.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  port: 5433,
  database: "jws_demo_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# Enable server for integration tests that make HTTP requests
# Integration tests (e.g., outbound_request_test.exs) need this to test
# the Client module sending signed requests to the mock partner endpoint
config :jws_demo, JwsDemoWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "9Vq8apg1YyoJxUz0EajM3cDIayFcS3f4IphxqRrXErpnHbUjrrgTvKKl5u/7eEW7",
  server: true

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime
