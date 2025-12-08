defmodule JwsDemoWeb.Router do
  use JwsDemoWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Pipeline for JWS-authenticated API endpoints
  # Note: :get_jwk option will be configured in endpoint or via config
  # For now, this is a placeholder - will be wired up with JWKS cache in Commit 8
  pipeline :api_authenticated do
    plug :accepts, ["json"]
    # VerifyJWSPlug will be added here when JWKS cache is ready (Commit 8)
  end

  # JWKS endpoint (standard location per RFC 8414)
  scope "/.well-known", JwsDemoWeb do
    pipe_through :api

    get "/jwks.json", JWKSController, :index
  end

  scope "/api/v1", JwsDemoWeb do
    pipe_through :api

    # Authorization endpoint (JWS verification will be added in integration tests)
    post "/authorizations", AuthorizationController, :create
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
