# JWS Signature Verification with OpenSSL

This document demonstrates independent verification of JWS signatures using standard OpenSSL tools.

For internal reverification, refer to the contents of `test/jws_demo/integration/authorization_flow_test.exs`
which you can execute with verbose output:

```sh
TEST_VERBOSE=true mix test test/jws_demo/integration/authorization_flow_test.exs
```

## Purpose

In case of disputes or regulatory audits, you can prove the authenticity of a signed authorization **without access to our codebase** using only:
- OpenSSL (standard cryptographic toolkit)
- The verification package from our audit trail
- Basic command-line tools

## What This Proves

A successful OpenSSL verification proves:

1. **Authenticity**: The signature was created by the holder of the private key
2. **Integrity**: The payload has not been modified since signing
3. **Non-Repudiation**: The partner cannot credibly deny signing the payload

This is cryptographic proof that holds up in legal/regulatory contexts.

## Prerequisites

- OpenSSL 1.1.1 or later
- Basic command-line knowledge
- A verification package from our system

## Verification Package

Generate a verification package for any authorization:

```bash
# In the Phoenix app
iex> JwsDemo.JWS.Audit.generate_verification_package("txn_123", "/tmp/audit_pkg")
:ok
```

For your convenience in case you wish to follow along, an example audit package
is available in the `audit_demo` folder.

The package contains:
- `jws_original.txt` - Complete JWS signature (CRITICAL: exact bytes)
- `public_key.pem` - Partner's public key (PEM format)
- `public_key.jwk` - Partner's public key (JWK format, for reference)
- `payload_decoded.json` - Human-readable payload
- `VERIFICATION.md` - Instructions with context

## Verification Protocol

These commands assume your are located within the audit package folder: make
sure to adjust accordingly.

### Step 1: Extract JWS Components

JWS format: `BASE64URL(header).BASE64URL(payload).BASE64URL(signature)`

```bash
# Read the JWS
JWS=$(cat jws_original.txt)

# Extract parts
HEADER=$(echo "$JWS" | cut -d'.' -f1)
PAYLOAD=$(echo "$JWS" | cut -d'.' -f2)
SIGNATURE=$(echo "$JWS" | cut -d'.' -f3)

# Verify we have 3 parts
echo "Header: ${HEADER:0:40}..."
echo "Payload: ${PAYLOAD:0:40}..."
echo "Signature: ${SIGNATURE:0:40}..."
```

### Step 2: Create Signing Input

The signing input is `header.payload` (exactly as transmitted):

```bash
# CRITICAL: No newline at end
echo -n "${HEADER}.${PAYLOAD}" > signing_input.txt

# Verify it's correct
wc -c signing_input.txt  # Should match header length + 1 (dot) + payload length
```

### Step 3: Decode Signature

JWS uses raw ECDSA format (R||S concatenation). OpenSSL requires DER format.

Use our helper script to convert the signature into the format expected by OpenSSL.

Make sure to adapt the path to the script, this assumes you're located in `audit_demo` or
another direct descendent of the project root.

```bash
# Requires Elixir
elixir ../scripts/convert_signature_to_der.exs "$SIGNATURE" > signature.der
```

### Step 4: Verify with OpenSSL

```bash
openssl dgst -sha256 \
  -verify public_key.pem \
  -signature signature.der \
  signing_input.txt
```

**Expected output:**
```
Verified OK
```

**If verification fails:**
```
Error verifying data
```

## What Verification Means

### ✅ "Verified OK"

The signature is valid. This proves:

1. **Authenticity**: Created by partner's private key holder
2. **Integrity**: Payload unchanged since signing
3. **Timestamp**: Valid at time of signing (check `iat` and `exp` in payload)
4. **Non-Repudiation**: Partner authorized this transaction

**In disputes:** This is cryptographic proof the partner authorized the transaction.

### ❌ "Verification Failure"

The signature is invalid. Possible reasons:

1. **Tampering**: Payload or signature modified
2. **Wrong Key**: Using incorrect public key
3. **Transcription Error**: JWS string copied incorrectly
4. **Format Issue**: Signing input has extra newline or whitespace

**Debug steps:**

```bash
# Check file sizes
ls -lh signing_input.txt signature.der public_key.pem

# Verify Base64URL decoding
echo "$SIGNATURE" | base64 -d 2>&1 | head -c 10 | xxd

# Check public key format
openssl pkey -pubin -in public_key.pem -text -noout
```

## Example Verification

Here's a complete worked example (drop into `audit_demo` to follow along):

```bash
# 1. Extract JWS (from verification package)
$ cat jws_original.txt
eyJhbGciOiJFUzI1NiIsImtpZCI6ImludGVncmF0aW9uLWtleS0yMDI1IiwidHlwIjoiSldUIn0.eyJhbW91bnQiOjEwMDAwMCwiY3VycmVuY3kiOiJFVVIiLCJkZXNjcmlwdGlvbiI6IlB1cmNoYXNlIE9yZGVyICMxMjM0NSIsImV4cCI6MTc2NTkwODA5MiwiaWF0IjoxNzY1OTA3NzkyLCJpbnN0cnVjdGlvbl9pZCI6InR4bl9pbnRlZ3JhdGlvbl8wMDEiLCJqdGkiOiI1NjUwMmJjNC0wNmYwLTQ0NDUtYmNjZi02ZDM2Y2Q1ZDg3MmQiLCJtZXJjaGFudF9pZCI6Im1lcmNoYW50X3h5eiJ9.i45CT8o3MYVfBPtNoRoRe-vzzi1ZdxmMp1GAHLsmpk2C99rEw09F8dRv2XAvKS_t7rUAOvZcQUyiGkBA-1HOWw

# 2. Extract parts
$ JWS=$(cat jws_original.txt)
$ HEADER=$(echo "$JWS" | cut -d'.' -f1)
$ PAYLOAD=$(echo "$JWS" | cut -d'.' -f2)
$ SIGNATURE=$(echo "$JWS" | cut -d'.' -f3)

# 3. Create signing input
$ echo -n "${HEADER}.${PAYLOAD}" > signing_input.txt
$ wc -c signing_input.txt

368 signing_input.txt

# 4. Convert signature to DER
$ elixir ../scripts/convert_signature_to_der.exs "$SIGNATURE" > signature.der

# 5. Verify
$ openssl dgst -sha256 -verify public_key.pem -signature signature.der signing_input.txt

Verified OK
```

## Payload Inspection

View the decoded payload:

```bash
# Decode payload
echo "$PAYLOAD" | base64 -d 2>/dev/null | jq .

# Output:
{
  "amount": 100000,
  "currency": "EUR",
  "description": "Purchase Order #12345",
  "exp": 1765908092,
  "iat": 1765907792,
  "instruction_id": "txn_integration_001",
  "jti": "56502bc4-06f0-4445-bccf-6d36cd5d872d",
  "merchant_id": "merchant_xyz"
}
```

Check timestamps:

```bash
# Convert Unix timestamps to readable dates
date -d @1765907792  # iat (issued at)
date -d @1765908092  # exp (expiration)
```

## Security Notes

### Why Store Original JWS?

**❌ WRONG: Reconstruct from payload**

```elixir
# This will FAIL verification
payload_json = Jason.encode!(payload)  # Different whitespace!
jws = "#{header}.#{Base.url_encode64(payload_json)}.#{signature}"
```

**✅ RIGHT: Store original JWS string**

```elixir
# Store the exact JWS received
audit_log.jws_signature = original_jws_string
```

JSON formatting (whitespace, key order) affects the signature. Reconstructing JWS will fail verification.

### Why Store Partner Key Snapshot?

Partners rotate keys regularly. To verify a 2-year-old authorization:

- ❌ Current JWKS won't have the old key
- ✅ Audit log has key snapshot from verification time

This is why `JwsDemo.JWS.Audit` stores the partner's public key with each audit log entry.

## Regulatory Compliance

This verification protocol satisfies requirements for the non-repudiation of instructions.

The verification package is:
- **Independent**: Works without our systems
- **Permanent**: Valid indefinitely (assuming key is stored)
- **Forensic**: Suitable for legal evidence

## Troubleshooting

### Common Issues

**1. "Verification Failure" with correct key**

Check for newlines in signing input:

```bash
# Should have NO newline at end
hexdump -C signing_input.txt | tail -n 1

# If you see "0a" (newline) at end, recreate without newline:
echo -n "${HEADER}.${PAYLOAD}" > signing_input.txt
```

**2. "unable to load Public Key"**

Verify PEM format:

```bash
openssl pkey -pubin -in public_key.pem -text -noout
```

Should show `Public-Key: (256 bit)` for ES256.

**3. Signature conversion fails**

Verify signature is Base64URL (not standard Base64):

```bash
# JWS uses Base64URL (no padding, - instead of +, _ instead of /)
echo "$SIGNATURE" | grep -E '[+/=]' || echo "Looks like Base64URL ✓"
```

## Related Documentation

- **Blog Post**: Audit Trails and Re-Verification
- **Test Reference**: `test/jws_demo/integration/authorization_flow_test.exs`
- **Audit Module**: `lib/jws_demo/jws/audit.ex`
- **RFC 7515**: JSON Web Signature (JWS) specification
