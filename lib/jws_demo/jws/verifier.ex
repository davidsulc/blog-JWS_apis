defmodule JwsDemo.JWS.Verifier do
  @moduledoc """
  Verifies JWS signatures with comprehensive validation.

  Implements the critical security checks from Blog Post 2 and Post 7:
  - Algorithm whitelist enforcement (prevent 'none' algorithm attack)
  - Cryptographic signature verification
  - Timestamp validation (iat, exp, nbf) with clock skew tolerance
  - Payload integrity verification

  ## Verification Process

  1. **Parse JWS**: Support both flattened JSON and compact formats
  2. **Algorithm Check**: Verify algorithm is in whitelist (default: only ES256)
  3. **Crypto Verification**: Use JOSE.JWS.verify_strict/3 for signature validation
  4. **Parse Payload**: Decode and parse JSON payload
  5. **Timestamp Validation**: Check iat, exp, nbf with clock skew tolerance
  6. **Return Claims**: Return verified payload or detailed error

  ## Clock Skew Tolerance

  Default 5 minutes (300 seconds) to handle:
  - Server time drift between partners
  - Network latency
  - Certificate validation timing

  ## Error Handling

  Returns detailed errors for security debugging:
  - `:invalid_signature` - Cryptographic verification failed (tampered or wrong key)
  - `:expired` - Token past expiration time
  - `:not_yet_valid` - Token issued in future (beyond clock skew)
  - `:algorithm_not_allowed` - Algorithm not in whitelist
  - `:invalid_format` - Malformed JWS structure
  - `:invalid_payload` - Payload not valid JSON

  ## Examples

      # Verify flattened JSON JWS
      jwk = JOSE.JWK.from_pem_file("priv/keys/partner_public.pem")
      jws = %{
        "payload" => "eyJhbW91bnQ...",
        "protected" => "eyJhbGciOiJFUzI1NiJ9",
        "signature" => "MEUCIQ..."
      }
      {:ok, claims} = Verifier.verify(jws, jwk)

      # Verify compact JWS
      compact_jws = "eyJhbGc...header.eyJhbW...payload.MEUCIQ...signature"
      {:ok, claims} = Verifier.verify(compact_jws, jwk)

      # Verification with custom clock skew
      {:ok, claims} = Verifier.verify(jws, jwk, clock_skew_seconds: 60)

  """

  @default_allowed_algorithms ["ES256"]
  @default_clock_skew_seconds 300

  @doc """
  Verifies a JWS signature with comprehensive validation.

  ## Options

  - `:allowed_algorithms` (default: ["ES256"]) - Whitelist of allowed algorithms
  - `:clock_skew_seconds` (default: 300) - Clock skew tolerance in seconds

  ## Returns

  - `{:ok, verified_payload}` - Signature valid, payload verified
  - `{:error, reason}` - Verification failed with specific reason

  ## Examples

      {:ok, claims} = verify(jws, public_key)
      assert claims["amount"] == 50_000

      {:error, :expired} = verify(old_jws, public_key)
      {:error, :invalid_signature} = verify(tampered_jws, public_key)

  """
  @spec verify(String.t() | map(), JOSE.JWK.t(), keyword()) :: {:ok, map()} | {:error, atom()}
  def verify(jws, jwk, opts \\ []) do
    allowed_algorithms = Keyword.get(opts, :allowed_algorithms, @default_allowed_algorithms)
    clock_skew_seconds = Keyword.get(opts, :clock_skew_seconds, @default_clock_skew_seconds)

    with {:ok, compact_jws} <- normalize_to_compact(jws),
         {:ok, header} <- extract_header(compact_jws),
         :ok <- check_algorithm(header, allowed_algorithms),
         {:ok, payload_json} <- verify_signature(compact_jws, jwk, allowed_algorithms),
         {:ok, payload} <- parse_payload(payload_json),
         :ok <- validate_timestamps(payload, clock_skew_seconds) do
      {:ok, payload}
    end
  end

  # Private functions

  # Normalize flattened JSON or compact format to compact string
  defp normalize_to_compact(jws) when is_binary(jws), do: {:ok, jws}

  defp normalize_to_compact(%{"protected" => header, "payload" => payload, "signature" => sig}) do
    {:ok, "#{header}.#{payload}.#{sig}"}
  end

  defp normalize_to_compact(_), do: {:error, :invalid_format}

  # Extract and decode the protected header
  defp extract_header(compact_jws) do
    case String.split(compact_jws, ".") do
      [header_b64, _payload_b64, _sig_b64] ->
        case Base.url_decode64(header_b64, padding: false) do
          {:ok, header_json} ->
            case Jason.decode(header_json) do
              {:ok, header} -> {:ok, header}
              {:error, _} -> {:error, :invalid_format}
            end

          :error ->
            {:error, :invalid_format}
        end

      _ ->
        {:error, :invalid_format}
    end
  rescue
    _ -> {:error, :invalid_format}
  end

  # Check algorithm against whitelist (CRITICAL: prevents 'none' algorithm attack)
  defp check_algorithm(%{"alg" => alg}, allowed_algorithms) do
    if alg in allowed_algorithms do
      :ok
    else
      {:error, :algorithm_not_allowed}
    end
  end

  defp check_algorithm(_, _), do: {:error, :invalid_format}

  # Perform cryptographic signature verification
  defp verify_signature(compact_jws, jwk, allowed_algorithms) do
    # Use verify_strict to enforce algorithm whitelist at crypto level
    case JOSE.JWS.verify_strict(jwk, allowed_algorithms, compact_jws) do
      {true, payload_json, _jws} ->
        {:ok, payload_json}

      {false, _, _} ->
        {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  # Parse payload JSON
  defp parse_payload(payload_json) do
    case Jason.decode(payload_json) do
      {:ok, payload} -> {:ok, payload}
      {:error, _} -> {:error, :invalid_payload}
    end
  rescue
    _ -> {:error, :invalid_payload}
  end

  # Validate timestamps (iat, exp, nbf) with clock skew tolerance
  defp validate_timestamps(payload, clock_skew_seconds) do
    now = System.system_time(:second)

    with :ok <- check_not_before(payload, now, clock_skew_seconds),
         :ok <- check_expiration(payload, now, clock_skew_seconds),
         :ok <- check_issued_at(payload, now, clock_skew_seconds) do
      :ok
    end
  end

  # Check nbf (not before) claim
  defp check_not_before(%{"nbf" => nbf}, now, clock_skew) when is_integer(nbf) do
    if now + clock_skew >= nbf do
      :ok
    else
      {:error, :not_yet_valid}
    end
  end

  defp check_not_before(_, _, _), do: :ok

  # Check exp (expiration) claim
  defp check_expiration(%{"exp" => exp}, now, clock_skew) when is_integer(exp) do
    if now - clock_skew <= exp do
      :ok
    else
      {:error, :expired}
    end
  end

  defp check_expiration(_, _, _), do: :ok

  # Check iat (issued at) claim - reject if issued too far in future
  defp check_issued_at(%{"iat" => iat}, now, clock_skew) when is_integer(iat) do
    if iat - clock_skew <= now do
      :ok
    else
      {:error, :not_yet_valid}
    end
  end

  defp check_issued_at(_, _, _), do: :ok
end
