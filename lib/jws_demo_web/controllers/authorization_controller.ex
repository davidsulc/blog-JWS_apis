defmodule JwsDemoWeb.AuthorizationController do
  @moduledoc """
  Handles authorization requests with JWS signatures.

  This controller demonstrates:
  - Processing JWS-signed authorization requests
  - Accessing verified payload from VerifyJWSPlug
  - Simulating authorization approval/rejection
  - Returning authorization results

  ## Request Flow

  1. Client signs authorization payload with JWS
  2. VerifyJWSPlug verifies signature and extracts payload
  3. Controller receives verified payload in conn.assigns
  4. Controller processes authorization (approve/reject)
  5. Returns authorization result with instruction_id

  ## Example Request

  POST /api/v1/authorizations
  Headers:
    X-Partner-ID: partner_abc
    Content-Type: application/json

  Body (Flattened JSON JWS):
  ```json
  {
    "payload": "eyJpbnN0cnVjdGlvbl9pZCI6InR4bl8xMjMiLCJhbW91bnQiOjUwMDAwfQ",
    "protected": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InBhcnRuZXIta2V5In0",
    "signature": "MEUCIQD..."
  }
  ```

  ## Example Response (Success)

  ```json
  {
    "status": "approved",
    "instruction_id": "txn_123",
    "amount": 50000,
    "currency": "EUR",
    "verified_at": "2025-01-15T10:30:00Z"
  }
  ```

  ## Non-Repudiation

  The verified JWS signature proves:
  1. Partner authorized this specific request
  2. Payload has not been tampered with
  3. Request timestamp is valid and not expired
  4. Partner cannot credibly deny authorization

  This is the foundation of non-repudiation in financial APIs.

  """

  use JwsDemoWeb, :controller
  require Logger

  @doc """
  Creates a new authorization from a verified JWS request.

  Expects verified payload in conn.assigns.verified_authorization
  (populated by VerifyJWSPlug).

  Returns 200 with authorization result or 400 for invalid requests.
  """
  def create(conn, _params) do
    # Extract verified payload from plug
    verified_payload = conn.assigns[:verified_authorization]
    partner_id = conn.assigns[:partner_id]

    case process_authorization(verified_payload, partner_id) do
      {:ok, result} ->
        Logger.info("Authorization approved: #{result.instruction_id}, partner: #{partner_id}")

        conn
        |> put_status(:ok)
        |> json(result)

      {:error, reason} ->
        Logger.warning("Authorization rejected: #{inspect(reason)}, partner: #{partner_id}")

        conn
        |> put_status(:bad_request)
        |> json(%{error: "authorization_failed", message: format_error(reason)})
    end
  end

  # Private functions

  # Process the authorization request
  defp process_authorization(payload, partner_id) do
    with :ok <- validate_required_fields(payload),
         :ok <- validate_amount(payload) do
      # Simulate authorization approval
      # In production: check balances, fraud detection, compliance, etc.

      result = %{
        status: "approved",
        instruction_id: payload["instruction_id"],
        amount: payload["amount"],
        currency: Map.get(payload, "currency", "USD"),
        partner_id: partner_id,
        verified_at: DateTime.utc_now() |> DateTime.to_iso8601(),
        # Include JWT claims for reference
        jti: payload["jti"],
        exp: payload["exp"]
      }

      {:ok, result}
    end
  end

  # Validate required fields in authorization payload
  defp validate_required_fields(payload) do
    required_fields = ["instruction_id", "amount"]

    missing_fields =
      Enum.filter(required_fields, fn field ->
        not Map.has_key?(payload, field) or is_nil(payload[field])
      end)

    case missing_fields do
      [] -> :ok
      fields -> {:error, {:missing_fields, fields}}
    end
  end

  # Validate amount is positive
  defp validate_amount(%{"amount" => amount}) when is_number(amount) and amount > 0 do
    :ok
  end

  defp validate_amount(%{"amount" => amount}) when is_number(amount) do
    {:error, {:invalid_amount, "Amount must be positive"}}
  end

  defp validate_amount(_) do
    {:error, {:invalid_amount, "Amount must be a number"}}
  end

  # Format error messages
  defp format_error({:missing_fields, fields}) do
    "Missing required fields: #{Enum.join(fields, ", ")}"
  end

  defp format_error({:invalid_amount, msg}), do: msg

  defp format_error(reason), do: "Authorization failed: #{inspect(reason)}"
end
