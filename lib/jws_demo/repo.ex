defmodule JwsDemo.Repo do
  use Ecto.Repo,
    otp_app: :jws_demo,
    adapter: Ecto.Adapters.Postgres
end
