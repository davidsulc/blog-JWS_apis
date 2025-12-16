defmodule JwsDemo.Partners.PartnerConfig do
  @moduledoc """
  Configuration for partner JWS verification.

  Stores per-partner settings for JWKS fetching, verification rules,
  and operational parameters like clock skew tolerance.

  From Blog Post 4: Multi-tenant JWKS management requires per-partner
  configuration to handle different algorithms, clock drift, and JWKS endpoints.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "partner_configs" do
    field :jwks_url, :string
    field :jwks_cache_ttl, :integer, default: 900
    field :allowed_algorithms, {:array, :string}, default: ["ES256"]
    field :clock_skew_tolerance, :integer, default: 300

    belongs_to :partner, JwsDemo.Partners.Partner

    timestamps()
  end

  @doc false
  def changeset(partner_config, attrs) do
    partner_config
    |> cast(attrs, [
      :partner_id,
      :jwks_url,
      :jwks_cache_ttl,
      :allowed_algorithms,
      :clock_skew_tolerance
    ])
    |> validate_required([:partner_id, :jwks_url])
    |> validate_number(:jwks_cache_ttl, greater_than: 0)
    |> validate_number(:clock_skew_tolerance, greater_than_or_equal_to: 0)
    |> unique_constraint(:partner_id)
  end
end
