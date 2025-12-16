defmodule JwsDemoWeb.VerifyJWSPlug do
  @moduledoc """
  Phoenix Plug for JWS signature verification.

  Verifies incoming requests signed with JWS, extracting and validating the signature
  before the request reaches the controller.

  ## Purpose

  This plug demonstrates:
  - Integration of JWS verification into Phoenix pipeline
  - Partner identification via headers
  - Error handling with helpful debugging messages
  - Verified payload assignment to conn.assigns for controllers

  ## Request Flow

  1. Extract `X-Partner-ID` header (simplified partner identification)
  2. Parse JWS from request body (expects flattened JSON or compact format)
  3. Fetch partner's public key (from JWKS cache or config)
  4. Verify signature using JWS.Verifier
  5. Assign verified payload and audit data to conn.assigns:
     - `verified_authorization` - Verified payload claims
     - `partner_id` - Partner identifier
     - `jws_original` - Original JWS (for audit logging)
     - `partner_jwk` - Partner's public key (for audit logging)
  6. If verification fails, return 401 with detailed error

  ## Configuration

  The plug accepts options:
  - `:get_jwk` - Function (partner_id -> {:ok, jwk} | {:error, reason})
  - `:allowed_algorithms` - Algorithm whitelist (default: ["ES256"])
  - `:clock_skew_seconds` - Clock skew tolerance (default: 300)

  ## Example Usage

      # In router.ex
      pipeline :api_authenticated do
        plug :accepts, ["json"]
        plug JwsDemoWeb.VerifyJWSPlug, get_jwk: &MyApp.get_partner_key/1
      end

      scope "/api/v1", JwsDemoWeb do
        pipe_through :api_authenticated

        post "/authorizations", AuthorizationController, :create
      end

  ## Simplified Demo Version

  This demo uses `X-Partner-ID` header for partner identification. In production:
  - Use mTLS with client certificates for partner authentication
  - Extract partner_id from certificate CN or SAN
  - Implement proper JWKS caching with TTL and rotation

  ## Error Responses

  Returns 401 with JSON body on failure:
  ```json
  {
    "error": "invalid_signature",
    "message": "JWS signature verification failed",
    "partner_id": "partner_abc"
  }
  ```

  """

  import Plug.Conn
  require Logger

  alias JwsDemo.JWS.Verifier

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, opts) do
    with {:ok, partner_id} <- extract_partner_id(conn),
         {:ok, jws} <- extract_jws(conn),
         {:ok, kid} <- extract_kid(jws),
         {:ok, jwk} <- get_partner_key(partner_id, kid, opts),
         {:ok, verified_payload} <- verify_signature(jws, jwk, opts) do
      # SUCCESS: Assign verified payload and audit data to conn
      conn
      |> assign(:verified_authorization, verified_payload)
      |> assign(:partner_id, partner_id)
      |> assign(:jws_original, jws)
      |> assign(:partner_jwk, jwk)
    else
      {:error, reason} ->
        handle_verification_error(conn, reason)
    end
  end

  # Private functions

  # Extract partner_id from X-Partner-ID header
  defp extract_partner_id(conn) do
    case get_req_header(conn, "x-partner-id") do
      [partner_id | _] when is_binary(partner_id) and partner_id != "" ->
        {:ok, partner_id}

      _ ->
        {:error, {:missing_header, "X-Partner-ID header required"}}
    end
  end

  # Extract JWS from request body
  defp extract_jws(conn) do
    case conn.body_params do
      %{"payload" => _, "protected" => _, "signature" => _} = jws ->
        # Flattened JSON format
        {:ok, jws}

      %{"jws" => compact_jws} when is_binary(compact_jws) ->
        # Compact format in "jws" field
        {:ok, compact_jws}

      params when is_binary(params) ->
        # Raw compact JWS string
        {:ok, params}

      _ ->
        {:error, {:invalid_body, "Request body must contain JWS (flattened JSON or compact)"}}
    end
  end

  # Extract kid (Key ID) from JWS protected header
  defp extract_kid(jws) when is_map(jws) do
    # Flattened JSON format
    case Map.get(jws, "protected") do
      nil ->
        {:error, {:invalid_jws, "Missing 'protected' header in flattened JWS"}}

      protected_b64 ->
        decode_kid_from_header(protected_b64)
    end
  end

  defp extract_kid(jws) when is_binary(jws) do
    # Compact format: "header.payload.signature"
    case String.split(jws, ".") do
      [header_b64, _, _] ->
        decode_kid_from_header(header_b64)

      _ ->
        {:error, {:invalid_jws, "Invalid compact JWS format"}}
    end
  end

  defp decode_kid_from_header(header_b64) when is_binary(header_b64) do
    with {:ok, header_json} <- decode_jws_header(header_b64),
         {:ok, header} <- parse_json(header_json) do
      fetch_kid(header)
    end
  end

  defp decode_kid_from_header(header_b64) when not is_binary(header_b64) do
    {:error, {:invalid_jws, "JWS header must be a string"}}
  end

  defp decode_jws_header(header) when is_binary(header) do
    with :error <- Base.url_decode64(header, padding: false) do
      {:error, {:invalid_jws, "Failed to decode JWS header"}}
    end
  end

  defp parse_json(json) do
    with {:error, _} <- Jason.decode(json) do
      {:error, {:invalid_jws, "Failed to parse JWS header"}}
    end
  end

  defp fetch_kid(%{"kid" => kid}) when is_binary(kid), do: {:ok, kid}
  defp fetch_kid(%{"kid" => kid}) when not is_binary(kid), do: {:error, {:invalid_kid, "kid must be a string"}}
  defp fetch_kid(%{}), do: {:error, {:missing_kid, "JWS header must include 'kid' (Key ID)"}}

  # Get partner's public key (JWK) using partner_id and kid
  defp get_partner_key(partner_id, kid, opts) do
    case Keyword.get(opts, :get_jwk) do
      nil ->
        # No key provider configured - fail with helpful error
        {:error, {:no_key_provider, "Plug not configured with :get_jwk option"}}

      get_jwk_fn when is_function(get_jwk_fn, 2) ->
        case get_jwk_fn.(partner_id, kid) do
          {:ok, jwk} ->
            {:ok, jwk}

          {:error, reason} ->
            {:error, {:key_fetch_failed, reason}}

          _ ->
            {:error, {:key_fetch_failed, :invalid_return_value}}
        end

      _ ->
        {:error, {:no_key_provider, ":get_jwk must be a function that takes (partner_id, kid)"}}
    end
  end

  # Verify JWS signature
  defp verify_signature(jws, jwk, opts) do
    verifier_opts = [
      allowed_algorithms: Keyword.get(opts, :allowed_algorithms, ["ES256"]),
      clock_skew_seconds: Keyword.get(opts, :clock_skew_seconds, 300)
    ]

    case Verifier.verify(jws, jwk, verifier_opts) do
      {:ok, verified_payload} ->
        {:ok, verified_payload}

      {:error, reason} ->
        {:error, {:verification_failed, reason}}
    end
  end

  # Handle verification errors with 401 response
  defp handle_verification_error(conn, {error_type, details}) do
    partner_id = get_req_header(conn, "x-partner-id") |> List.first()

    error_response = %{
      error: to_string(error_type),
      message: format_error_message(error_type, details),
      partner_id: partner_id
    }

    Logger.warning(
      "JWS verification failed: #{inspect(error_type)}, partner: #{partner_id}, details: #{inspect(details)}"
    )

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(401, Jason.encode!(error_response))
    |> halt()
  end

  # Format user-friendly error messages
  defp format_error_message(:missing_header, msg), do: msg
  defp format_error_message(:invalid_body, msg), do: msg
  defp format_error_message(:no_key_provider, msg), do: msg

  defp format_error_message(:key_fetch_failed, reason) do
    "Failed to fetch partner public key: #{inspect(reason)}"
  end

  defp format_error_message(:verification_failed, :invalid_signature) do
    "JWS signature verification failed - signature invalid or tampered payload"
  end

  defp format_error_message(:verification_failed, :expired) do
    "JWS token expired - request must be signed with current timestamp"
  end

  defp format_error_message(:verification_failed, :not_yet_valid) do
    "JWS token not yet valid - issued timestamp is in the future"
  end

  defp format_error_message(:verification_failed, :algorithm_not_allowed) do
    "JWS algorithm not allowed - only ES256 is supported"
  end

  defp format_error_message(:verification_failed, reason) do
    "JWS verification failed: #{inspect(reason)}"
  end
end
