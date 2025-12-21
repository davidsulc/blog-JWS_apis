defmodule JwsDemo.JWS.Audit do
  @moduledoc """
  Audit trail for JWS-signed authorizations with re-verification support.

  This module demonstrates the "forever proof" concept from Blog Post 5:
  - Store ORIGINAL JWS string (never reconstruct from payload)
  - Store partner public key snapshot at verification time
  - Enable re-verification months/years later for disputes
  - Generate OpenSSL verification packages for independent audit

  ## Why Store Original JWS?

  CRITICAL: Never reconstruct JWS from payload. JSON formatting differences
  (whitespace, key ordering) will invalidate the signature.

  ```elixir
  # WRONG: Reconstruct JWS
  payload_json = Jason.encode!(payload)  # Different whitespace!
  # Signature verification will FAIL

  # RIGHT: Store original JWS string
  audit_log.jws_signature  # Exact bytes that were signed
  # Signature verification will SUCCEED
  ```

  ## Why Store Public Key Snapshot?

  Partners rotate keys over time. To re-verify a 2-year-old authorization:
  - Current JWKS won't have the old key
  - Must use the public key that was active at verification time
  - Store JWK snapshot in audit log

  ## Re-Verification Process

  1. Load audit log by instruction_id
  2. Extract original JWS string
  3. Extract partner public key snapshot (JWK)
  4. Verify using JWS.Verifier with stored key
  5. Compare result with stored payload

  ## OpenSSL Verification Package

  For regulatory compliance or legal disputes, generate a package containing:
  - Original JWS
  - Public key (PEM format)
  - Payload (JSON)
  - Verification instructions

  This allows independent verification without our codebase.

  ## Examples

      # Store authorization
      {:ok, audit_log} = Audit.log_authorization(
        verified_payload,
        partner_jwk,
        %{jws_signature: original_jws, partner_id: "partner_abc"}
      )

      # Re-verify later
      {:ok, verified} = Audit.re_verify("txn_123")

      # Generate verification package
      :ok = Audit.generate_verification_package("txn_123", "/tmp/audit")

  """

  require Logger
  alias JwsDemo.Repo
  alias JwsDemo.AuditLogs.AuditLog
  alias JwsDemo.JWS.Verifier

  @doc """
  Logs an authorization to the audit trail (both inbound and outbound).

  ## Parameters
  - `verified_payload` - The verified payload from JWS.Verifier
  - `partner_jwk` - Partner's public key (JOSE.JWK) used for verification
  - `metadata` - Map containing:
    - `:jws_signature` (required) - Original JWS string
    - `:partner_id` (required) - Partner identifier
    - `:direction` (required) - "inbound" or "outbound"
    - `:uri` (required) - Endpoint URI
    - `:verification_algorithm` - Algorithm used (default: "ES256")
    - `:verification_kid` - Key ID used
    - `:response_status` - HTTP status code (for outbound)
    - `:response_body` - Response data (for outbound)

  ## Examples

  Inbound (receiving from partner):
      Audit.log_authorization(verified_payload, partner_jwk, %{
        jws_signature: original_jws,
        partner_id: "partner_abc",
        direction: "inbound",
        uri: "/api/v1/authorizations"
      })

  Outbound (sending to partner):
      Audit.log_authorization(verified_payload, our_private_key, %{
        jws_signature: original_jws,
        partner_id: "partner_xyz",
        direction: "outbound",
        uri: "https://partner.example.com/webhooks",
        response_status: 200,
        response_body: %{"status" => "received"}
      })

  ## Returns
  - `{:ok, audit_log}` - Audit log record
  - `{:error, changeset}` - If validation fails
  """
  @spec log_authorization(map(), JOSE.JWK.t(), map()) ::
          {:ok, AuditLog.t()} | {:error, Ecto.Changeset.t()}
  def log_authorization(verified_payload, partner_jwk, metadata) do
    # Get partner from database
    partner_id_str = Map.fetch!(metadata, :partner_id)

    # Query Partners table to get partner record
    partner =
      case Repo.get_by(JwsDemo.Partners.Partner, partner_id: partner_id_str) do
        nil ->
          # DEMO SIMPLIFICATION: Auto-create partners for tests
          # PRODUCTION: Pre-register all partners in database with proper validation
          # and onboarding verification before allowing any requests
          %JwsDemo.Partners.Partner{}
          |> JwsDemo.Partners.Partner.changeset(%{
            partner_id: partner_id_str,
            name: "Auto-created: #{partner_id_str}",
            active: true
          })
          |> Repo.insert!()

        partner ->
          partner
      end

    partner_db_id = partner.id

    # Convert JWK to map for storage
    {_jwk, jwk_map} = JOSE.JWK.to_map(partner_jwk)

    attrs = %{
      partner_id: partner_db_id,
      instruction_id: verified_payload["instruction_id"],
      jws_signature: Map.fetch!(metadata, :jws_signature),
      partner_public_key: jwk_map,
      payload: verified_payload,
      verified_at: DateTime.utc_now(),
      verification_algorithm: Map.get(metadata, :verification_algorithm, "ES256"),
      verification_kid: Map.get(metadata, :verification_kid),
      # Bidirectional audit trail fields
      direction: Map.get(metadata, :direction, "inbound"),
      uri: Map.get(metadata, :uri, ""),
      response_status: Map.get(metadata, :response_status),
      response_body: Map.get(metadata, :response_body)
    }

    %AuditLog{}
    |> AuditLog.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Re-verifies an authorization using stored JWS and public key.

  ## Parameters
  - `instruction_id` - Instruction ID to re-verify

  ## Returns
  - `{:ok, verified_payload}` - Re-verification successful
  - `{:error, reason}` - If not found or verification fails

  ## Example

      {:ok, verified} = Audit.re_verify("txn_123")
      assert verified["amount"] == 50_000

  """
  @spec re_verify(String.t()) :: {:ok, map()} | {:error, term()}
  def re_verify(instruction_id) do
    case Repo.get_by(AuditLog, instruction_id: instruction_id) do
      nil ->
        {:error, :audit_log_not_found}

      audit_log ->
        # Convert stored JWK map back to JOSE.JWK
        partner_jwk = JOSE.JWK.from(audit_log.partner_public_key)

        # Verify using original JWS and stored key
        case Verifier.verify(audit_log.jws_signature, partner_jwk) do
          {:ok, verified_payload} ->
            # Verify it matches stored payload
            if payloads_match?(verified_payload, audit_log.payload) do
              Logger.info("Re-verification successful: #{instruction_id}")
              {:ok, verified_payload}
            else
              Logger.error("Re-verification payload mismatch: #{instruction_id}")
              {:error, :payload_mismatch}
            end

          {:error, reason} ->
            Logger.error("Re-verification failed: #{instruction_id}, reason: #{inspect(reason)}")
            {:error, {:verification_failed, reason}}
        end
    end
  end

  @doc """
  Generates an OpenSSL verification package for independent audit.

  Creates a directory with files for OpenSSL-based verification:
  - `jws_original.txt` - Complete JWS signature
  - `public_key.pem` - Partner's public key in PEM format
  - `public_key.jwk` - Partner's public key in JWK format
  - `payload_decoded.json` - Human-readable payload
  - `VERIFICATION.md` - Step-by-step verification instructions

  ## Parameters
  - `instruction_id` - Instruction ID to generate package for
  - `output_dir` - Directory to create package in

  ## Returns
  - `:ok` - Package created successfully
  - `{:error, reason}` - If failed

  ## Example

      :ok = Audit.generate_verification_package("txn_123", "/tmp/audit_pkg")

  """
  @spec generate_verification_package(String.t(), String.t()) :: :ok | {:error, term()}
  def generate_verification_package(instruction_id, output_dir) do
    case Repo.get_by(AuditLog, instruction_id: instruction_id) do
      nil ->
        {:error, :audit_log_not_found}

      audit_log ->
        # Create output directory
        File.mkdir_p!(output_dir)

        # Write original JWS
        File.write!(
          Path.join(output_dir, "jws_original.txt"),
          audit_log.jws_signature
        )

        # Write public key in JWK format
        File.write!(
          Path.join(output_dir, "public_key.jwk"),
          Jason.encode!(audit_log.partner_public_key, pretty: true)
        )

        # Convert JWK to PEM and write
        partner_jwk = JOSE.JWK.from(audit_log.partner_public_key)
        # Convert to public key only (remove private components if any)
        public_jwk = JOSE.JWK.to_public(partner_jwk)
        # to_pem returns a tuple {jwk_record, pem_string}
        {_jwk, pem_string} = JOSE.JWK.to_pem(public_jwk)

        File.write!(
          Path.join(output_dir, "public_key.pem"),
          pem_string
        )

        # Write decoded payload
        File.write!(
          Path.join(output_dir, "payload_decoded.json"),
          Jason.encode!(audit_log.payload, pretty: true)
        )

        # Write verification instructions
        verification_md = """
        # JWS Verification Package

        ## Authorization Details

        - **Instruction ID:** #{audit_log.instruction_id}
        - **Verified At:** #{audit_log.verified_at}
        - **Algorithm:** #{audit_log.verification_algorithm}
        - **Key ID:** #{audit_log.verification_kid || "N/A"}

        ## Files

        - `jws_original.txt` - Complete JWS signature (CRITICAL: exact bytes)
        - `public_key.pem` - Partner public key (PEM format for OpenSSL)
        - `public_key.jwk` - Partner public key (JWK format for reference)
        - `payload_decoded.json` - Human-readable payload

        ## OpenSSL Verification Steps

        See AUDIT.md in the main repository for complete OpenSSL verification protocol.

        ### Quick Verification

        1. Extract JWS components:
           ```bash
           JWS=$(cat jws_original.txt)
           HEADER=$(echo $JWS | cut -d'.' -f1)
           PAYLOAD=$(echo $JWS | cut -d'.' -f2)
           SIGNATURE=$(echo $JWS | cut -d'.' -f3)
           ```

        2. Create signing input:
           ```bash
           echo -n "${HEADER}.${PAYLOAD}" > signing_input.txt
           ```

        3. Convert signature to DER format (requires helper script)

        4. Verify with OpenSSL:
           ```bash
           openssl dgst -sha256 -verify public_key.pem \\
             -signature signature.der signing_input.txt
           ```

           Expected output: `Verified OK`

        ## What This Proves

        A successful verification proves:
        1. The partner's private key holder signed this exact payload
        2. The payload has not been modified since signing
        3. The signature was created with the specified algorithm (#{audit_log.verification_algorithm})
        4. The partner cannot credibly deny authorizing this transaction

        This is cryptographic non-repudiation.

        ## Payload Contents

        ```json
        #{Jason.encode!(audit_log.payload, pretty: true)}
        ```

        ---

        Generated: #{DateTime.utc_now() |> DateTime.to_iso8601()}
        """

        File.write!(
          Path.join(output_dir, "VERIFICATION.md"),
          verification_md
        )

        Logger.info("Verification package generated: #{output_dir}")
        :ok
    end
  rescue
    error ->
      Logger.error("Failed to generate verification package: #{inspect(error)}")
      {:error, {:generation_failed, error}}
  end

  # Private functions

  # Compare two payloads, ignoring claims that may differ on re-verification
  defp payloads_match?(verified, stored) do
    # Compare all fields except iat/exp/nbf which may be checked differently
    # In production, you might want stricter comparison
    Map.drop(verified, ["iat", "exp", "nbf", "jti"]) ==
      Map.drop(stored, ["iat", "exp", "nbf", "jti"])
  end
end
