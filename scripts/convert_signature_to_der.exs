#!/usr/bin/env elixir

# Convert JWS signature (Base64URL raw R||S) to DER format for OpenSSL
#
# Usage: mix run scripts/convert_signature_to_der.exs <base64url_signature>
# Output: DER-encoded signature (binary) on stdout
#
# Example:
#   mix run scripts/convert_signature_to_der.exs "kp1uhb-QhBi..." > signature.der
#   openssl dgst -sha256 -verify public_key.pem -signature signature.der signing_input.txt

defmodule SignatureConverter do
  @moduledoc """
  Converts JWS ECDSA signature from raw format (R||S concatenation) to DER format.

  JWS uses raw ECDSA format: 32 bytes R + 32 bytes S = 64 bytes total (for P-256)
  OpenSSL expects DER format: SEQUENCE { INTEGER r, INTEGER s }
  """

  @doc """
  Convert raw ECDSA signature to DER format.

  ## Parameters
  - `raw_sig` - 64 bytes (R||S concatenation)

  ## Returns
  - DER-encoded signature (binary)
  """
  def raw_to_der(raw_sig) when byte_size(raw_sig) == 64 do
    # Split into R and S (each 32 bytes for P-256)
    <<r::binary-size(32), s::binary-size(32)>> = raw_sig

    # Encode as DER SEQUENCE { INTEGER r, INTEGER s }
    r_der = encode_integer(r)
    s_der = encode_integer(s)

    # SEQUENCE tag (0x30) + length + contents
    inner = r_der <> s_der
    <<0x30, byte_size(inner)>> <> inner
  end

  def raw_to_der(raw_sig) do
    raise ArgumentError,
          "Expected 64 bytes for P-256 signature, got #{byte_size(raw_sig)} bytes"
  end

  # Encode integer as DER
  defp encode_integer(value) do
    # Remove leading zero bytes
    value = remove_leading_zeros(value)

    # Add leading zero if high bit is set (to keep it positive)
    value =
      case value do
        <<>> ->
          <<0>>

        <<high::8, _::binary>> when high >= 0x80 ->
          <<0>> <> value

        _ ->
          value
      end

    # INTEGER tag (0x02) + length + value
    <<0x02, byte_size(value)>> <> value
  end

  # Remove leading zero bytes but keep at least one byte
  defp remove_leading_zeros(<<0, rest::binary>>) when byte_size(rest) > 0 do
    remove_leading_zeros(rest)
  end

  defp remove_leading_zeros(value), do: value
end

# Main execution
case System.argv() do
  [signature_b64url] ->
    try do
      # Decode Base64URL to binary
      signature_raw = Base.url_decode64!(signature_b64url, padding: false)

      # Convert to DER
      signature_der = SignatureConverter.raw_to_der(signature_raw)

      # Write to stdout (binary)
      IO.binwrite(signature_der)
    rescue
      e in ArgumentError ->
        IO.puts(:stderr, "Error: #{Exception.message(e)}")
        System.halt(1)

      e ->
        IO.puts(:stderr, "Error: #{inspect(e)}")
        System.halt(1)
    end

  _ ->
    IO.puts(:stderr, """
    Usage: mix run scripts/convert_signature_to_der.exs <base64url_signature>

    Converts JWS ECDSA signature from raw format to DER format for OpenSSL verification.

    Example:
      $ JWS="eyJhbGc...header.eyJhbW...payload.kp1uhb...signature"
      $ SIGNATURE=$(echo "$JWS" | cut -d'.' -f3)
      $ mix run scripts/convert_signature_to_der.exs "$SIGNATURE" > signature.der
      $ openssl dgst -sha256 -verify public_key.pem -signature signature.der signing_input.txt

    See AUDIT.md for complete verification protocol.
    """)

    System.halt(1)
end
