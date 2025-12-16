defmodule JwsDemoWeb.Router do
  use JwsDemoWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Pipeline for JWS-authenticated API endpoints with signature verification
  # Verifies JWS signatures using partner public keys fetched from JWKS cache
  pipeline :api_authenticated do
    plug :accepts, ["json"]
    plug JwsDemoWeb.VerifyJWSPlug, get_jwk: &JwsDemo.JWS.JWKSCache.get_key/2
  end

  # JWKS endpoint (standard location per RFC 8414)
  scope "/.well-known", JwsDemoWeb do
    pipe_through :api

    get "/jwks.json", JWKSController, :index
  end

  scope "/api/v1", JwsDemoWeb do
    pipe_through :api_authenticated

    # Authorization endpoint with JWS signature verification via VerifyJWSPlug
    post "/authorizations", AuthorizationController, :create
  end

  # Mock partner endpoints (for testing outbound signed requests)
  # These simulate a partner's API receiving our signed webhooks
  scope "/mock/partner", JwsDemoWeb do
    pipe_through :api

    post "/webhooks", PartnerWebhookController, :receive_webhook
  end

  # Enable LiveDashboard in development
  if Application.compile_env(:jws_demo, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through [:fetch_session, :protect_from_forgery]

      live_dashboard "/dashboard", metrics: JwsDemoWeb.Telemetry
    end
  end
end
