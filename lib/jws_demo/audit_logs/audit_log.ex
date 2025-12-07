defmodule JwsDemo.AuditLogs.AuditLog do
  @moduledoc """
  Audit trail for signed authorization requests.

  Stores the ORIGINAL JWS signature, partner's public key snapshot, and verification
  metadata to enable re-verification years later during dispute resolution.

  From Blog Post 5: The "Forever Proof"
  - Store original JWS string (never reconstruct from payload due to JSON canonicalization)
  - Store partner's public key snapshot (in case they rotate/revoke keys)
  - Include verification metadata (algorithm, kid, timestamp)

  This enables cryptographic proof that survives:
  - Time (re-verify years later)
  - Disputes (mathematical proof vs "he said, she said")
  - Regulatory audits (independent verification with OpenSSL)
  """
  use Ecto.Schema
  import Ecto.Changeset

  schema "audit_logs" do
    field :instruction_id, :string
    field :jws_signature, :string
    field :partner_public_key, :map
    field :payload, :map
    field :verified_at, :utc_datetime
    field :verification_algorithm, :string
    field :verification_kid, :string

    belongs_to :partner, JwsDemo.Partners.Partner

    timestamps()
  end

  @doc false
  def changeset(audit_log, attrs) do
    audit_log
    |> cast(attrs, [
      :partner_id,
      :instruction_id,
      :jws_signature,
      :partner_public_key,
      :payload,
      :verified_at,
      :verification_algorithm,
      :verification_kid
    ])
    |> validate_required([
      :partner_id,
      :instruction_id,
      :jws_signature,
      :partner_public_key,
      :payload,
      :verified_at,
      :verification_algorithm
    ])
    |> unique_constraint(:instruction_id)
  end
end
