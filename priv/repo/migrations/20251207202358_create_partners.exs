defmodule JwsDemo.Repo.Migrations.CreatePartners do
  use Ecto.Migration

  def change do
    create table(:partners) do
      add :partner_id, :string, null: false
      add :name, :string, null: false
      add :active, :boolean, default: true, null: false

      timestamps()
    end

    create unique_index(:partners, [:partner_id])
    create index(:partners, [:active])
  end
end
