defmodule JwsDemo.Partners.Partner do
  @moduledoc """
  Represents a partner that sends signed authorization requests.

  Partners are organizations (e.g., issuer banks) that integrate with our API
  and sign their requests using JWS for non-repudiation.
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "partners" do
    field :partner_id, :string
    field :name, :string
    field :active, :boolean, default: true

    has_one :config, JwsDemo.Partners.PartnerConfig
    has_many :audit_logs, JwsDemo.AuditLogs.AuditLog

    timestamps()
  end

  @doc false
  def changeset(partner, attrs) do
    partner
    |> cast(attrs, [:partner_id, :name, :active])
    |> validate_required([:partner_id, :name])
    |> unique_constraint(:partner_id)
  end
end
