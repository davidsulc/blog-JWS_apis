defmodule JwsDemo.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      JwsDemoWeb.Telemetry,
      JwsDemo.Repo,
      {DNSCluster, query: Application.get_env(:jws_demo, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: JwsDemo.PubSub},
      # JWKS cache for multi-tenant key management
      JwsDemo.JWS.JWKSCache,
      # JWKS publisher for serving our public keys
      JwsDemo.JWS.JWKSPublisher,
      # Start to serve requests, typically the last entry
      JwsDemoWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: JwsDemo.Supervisor]

    with {:ok, pid} <- Supervisor.start_link(children, opts) do
      # Warm JWKS cache after startup to prevent cold-start latency
      # In demo mode, this logs but doesn't fetch real endpoints
      # In production, this would preload all partner JWKS
      JwsDemo.JWS.JWKSCache.warm_cache()

      {:ok, pid}
    end
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    JwsDemoWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
