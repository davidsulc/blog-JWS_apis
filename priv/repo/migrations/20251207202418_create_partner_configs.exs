defmodule JwsDemo.Repo.Migrations.CreatePartnerConfigs do
  use Ecto.Migration

  def change do
    create table(:partner_configs) do
      add :partner_id, references(:partners, on_delete: :delete_all), null: false
      add :jwks_url, :string, null: false
      add :jwks_cache_ttl, :integer, default: 900, null: false
      add :allowed_algorithms, {:array, :string}, default: ["ES256"], null: false
      add :clock_skew_tolerance, :integer, default: 300, null: false

      timestamps()
    end

    create unique_index(:partner_configs, [:partner_id])
  end
end
