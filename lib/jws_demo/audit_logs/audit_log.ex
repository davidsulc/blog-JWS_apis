defmodule JwsDemo.AuditLogs.AuditLog do
  @moduledoc """
  Audit trail for signed requests (both inbound and outbound).

  Stores the ORIGINAL JWS signature, partner's public key snapshot, and verification
  metadata to enable re-verification years later during dispute resolution.

  ## Bidirectional Audit Trail

  This schema tracks BOTH directions of signed requests:
  - **Inbound**: Requests we receive from partners (they sign, we verify)
  - **Outbound**: Requests we send to partners (we sign, they verify)

  ## From Blog Post 5: The "Forever Proof"

  - Store original JWS string (never reconstruct from payload due to JSON canonicalization)
  - Store partner's public key snapshot (in case they rotate/revoke keys)
  - Include verification metadata (algorithm, kid, timestamp)
  - Track URI and direction for complete audit context
  - Store response data for outbound requests

  This enables cryptographic proof that survives:
  - Time (re-verify years later)
  - Disputes (mathematical proof vs "he said, she said")
  - Regulatory audits (independent verification with OpenSSL)
  - Compliance (complete bidirectional audit trail)
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

    # Bidirectional audit trail fields
    field :direction, :string  # "inbound" or "outbound"
    field :uri, :string        # Endpoint URI
    field :response_status, :integer  # HTTP status code
    field :response_body, :map        # Response data

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
      :verification_kid,
      :direction,
      :uri,
      :response_status,
      :response_body
    ])
    |> validate_required([
      :partner_id,
      :instruction_id,
      :jws_signature,
      :partner_public_key,
      :payload,
      :verified_at,
      :verification_algorithm,
      :direction,
      :uri
    ])
    |> validate_inclusion(:direction, ["inbound", "outbound"])
    |> unique_constraint(:instruction_id)
  end
end
