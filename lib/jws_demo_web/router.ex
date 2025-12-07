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

  scope "/api/v1", JwsDemoWeb do
    pipe_through :api

    # Authorization endpoint (JWS verification will be added in integration tests)
    post "/authorizations", AuthorizationController, :create
  end

  # Enable LiveDashboard and Swoosh mailbox preview in development
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
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end
end
