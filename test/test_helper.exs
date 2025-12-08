# Capture log output during tests to keep console output clean
ExUnit.start(capture_log: true)
Ecto.Adapters.SQL.Sandbox.mode(JwsDemo.Repo, :manual)
