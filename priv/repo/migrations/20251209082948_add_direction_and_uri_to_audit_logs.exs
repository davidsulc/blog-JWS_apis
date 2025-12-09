defmodule JwsDemo.Repo.Migrations.AddDirectionAndUriToAuditLogs do
  use Ecto.Migration

  def change do
    alter table(:audit_logs) do
      # Direction: "inbound" (received from partners) or "outbound" (sent to partners)
      add :direction, :string, null: false, default: "inbound"

      # URI: The endpoint that was called
      # - Inbound: Our endpoint (e.g., "/api/v1/authorizations")
      # - Outbound: Partner's endpoint (e.g., "https://partner.example.com/webhooks")
      add :uri, :text, null: false, default: ""

      # HTTP status code of the response (for outbound requests)
      # - Inbound: Our response status (200, 400, etc.)
      # - Outbound: Partner's response status
      add :response_status, :integer

      # Response body (for outbound requests where we want to track partner's acknowledgment)
      add :response_body, :jsonb
    end

    # Create index for querying by direction
    create index(:audit_logs, [:direction])

    # Create index for querying by URI (for finding all requests to a specific endpoint)
    create index(:audit_logs, [:uri])
  end
end
