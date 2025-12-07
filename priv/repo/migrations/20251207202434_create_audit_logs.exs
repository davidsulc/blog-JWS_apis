defmodule JwsDemo.Repo.Migrations.CreateAuditLogs do
  use Ecto.Migration

  def change do
    create table(:audit_logs) do
      add :partner_id, references(:partners, on_delete: :restrict), null: false
      add :instruction_id, :string, null: false

      # CRITICAL: Store original JWS signature (never reconstruct)
      add :jws_signature, :text, null: false

      # Store partner public key snapshot (JWK format)
      add :partner_public_key, :jsonb, null: false

      # Parsed payload for querying
      add :payload, :jsonb, null: false

      # Verification metadata
      add :verified_at, :utc_datetime, null: false
      add :verification_algorithm, :string, null: false
      add :verification_kid, :string

      timestamps()
    end

    create unique_index(:audit_logs, [:instruction_id])
    create index(:audit_logs, [:partner_id])
    create index(:audit_logs, [:verified_at])
  end
end
