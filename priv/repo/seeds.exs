# Script for populating the database with test data
# Run with: mix run priv/repo/seeds.exs

alias JwsDemo.Repo
alias JwsDemo.Partners.{Partner, PartnerConfig}
import Ecto.Query

# Clear existing data (development only)
if Mix.env() == :dev do
  Repo.delete_all(PartnerConfig)
  Repo.delete_all(Partner)
  IO.puts("Cleared existing partners and configs")
end

# Partner ABC - Financial Institution
partner_abc =
  %Partner{}
  |> Partner.changeset(%{
    partner_id: "partner_abc",
    name: "ABC Financial Institution",
    active: true
  })
  |> Repo.insert!()

%PartnerConfig{}
|> PartnerConfig.changeset(%{
  partner_id: partner_abc.id,
  jwks_url: "https://partner-abc.example.com/.well-known/jwks.json",
  jwks_cache_ttl: 900,
  allowed_algorithms: ["ES256"],
  clock_skew_tolerance: 300
})
|> Repo.insert!()

IO.puts("✓ Created partner: ABC Financial Institution (partner_abc)")

# Partner XYZ - Payment Processor
partner_xyz =
  %Partner{}
  |> Partner.changeset(%{
    partner_id: "partner_xyz",
    name: "XYZ Payment Processor",
    active: true
  })
  |> Repo.insert!()

%PartnerConfig{}
|> PartnerConfig.changeset(%{
  partner_id: partner_xyz.id,
  jwks_url: "https://partner-xyz.example.com/.well-known/jwks.json",
  jwks_cache_ttl: 600,
  allowed_algorithms: ["ES256"],
  clock_skew_tolerance: 300
})
|> Repo.insert!()

IO.puts("✓ Created partner: XYZ Payment Processor (partner_xyz)")

# Partner Demo - For Testing
partner_demo =
  %Partner{}
  |> Partner.changeset(%{
    partner_id: "partner_demo",
    name: "Demo Partner Inc",
    active: true
  })
  |> Repo.insert!()

%PartnerConfig{}
|> PartnerConfig.changeset(%{
  partner_id: partner_demo.id,
  jwks_url: "http://localhost:4000/.well-known/jwks.json",
  jwks_cache_ttl: 300,
  allowed_algorithms: ["ES256"],
  clock_skew_tolerance: 300
})
|> Repo.insert!()

IO.puts("✓ Created partner: Demo Partner Inc (partner_demo)")

# Inactive partner for testing
partner_inactive =
  %Partner{}
  |> Partner.changeset(%{
    partner_id: "partner_inactive",
    name: "Inactive Partner LLC",
    active: false
  })
  |> Repo.insert!()

%PartnerConfig{}
|> PartnerConfig.changeset(%{
  partner_id: partner_inactive.id,
  jwks_url: "https://partner-inactive.example.com/.well-known/jwks.json",
  jwks_cache_ttl: 900,
  allowed_algorithms: ["ES256"],
  clock_skew_tolerance: 300
})
|> Repo.insert!()

IO.puts("✓ Created partner: Inactive Partner LLC (partner_inactive) - INACTIVE")

IO.puts("\n" <> String.duplicate("=", 60))
IO.puts("Database seeded successfully!")
IO.puts(String.duplicate("=", 60))
IO.puts("\nSummary:")
IO.puts("  - #{Repo.aggregate(Partner, :count)} partners created")
IO.puts("  - #{Repo.aggregate(PartnerConfig, :count)} partner configurations created")
IO.puts("  - #{Repo.aggregate(Partner |> Ecto.Query.where(active: true), :count)} active partners")
IO.puts("\nPartners:")
IO.puts("  1. partner_abc - ABC Financial Institution (ACTIVE)")
IO.puts("  2. partner_xyz - XYZ Payment Processor (ACTIVE)")
IO.puts("  3. partner_demo - Demo Partner Inc (ACTIVE)")
IO.puts("  4. partner_inactive - Inactive Partner LLC (INACTIVE)")
IO.puts("\nJWKS URLs:")
IO.puts("  - partner_abc: https://partner-abc.example.com/.well-known/jwks.json")
IO.puts("  - partner_xyz: https://partner-xyz.example.com/.well-known/jwks.json")
IO.puts("  - partner_demo: http://localhost:4000/.well-known/jwks.json")
IO.puts("\nTo use in tests, reference partners by partner_id (e.g., 'partner_abc')")
IO.puts(String.duplicate("=", 60))
