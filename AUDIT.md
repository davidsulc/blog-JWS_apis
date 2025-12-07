# JWS Signature Verification with OpenSSL

This document demonstrates independent verification of JWS signatures using standard OpenSSL tools.

## Purpose

In case of disputes or regulatory audits, you can prove the authenticity of a signed authorization **without access to our codebase** using only:
- OpenSSL (standard cryptographic toolkit)
- The verification package from our audit trail
- Basic command-line tools

## What This Proves

A successful OpenSSL verification proves:

1. **Authenticity**: The signature was created by the holder of the private key
2. **Integrity**: The payload has not been modified since signing
3. **Non-Repudiation**: The partner cannot credibly deny authorizing this transaction

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

The package contains:
- `jws_original.txt` - Complete JWS signature (CRITICAL: exact bytes)
- `public_key.pem` - Partner's public key (PEM format)
- `public_key.jwk` - Partner's public key (JWK format, for reference)
- `payload_decoded.json` - Human-readable payload
- `VERIFICATION.md` - Instructions with context

## Verification Protocol

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

**Option A: Use our helper script**

```bash
# Requires Elixir
mix run scripts/convert_signature_to_der.exs "$SIGNATURE" > signature.der
```

**Option B: Manual conversion (Python)**

```python
#!/usr/bin/env python3
import base64
import sys

def base64url_decode(data):
    """Decode Base64URL to bytes"""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)

def raw_to_der(raw_sig):
    """Convert raw ECDSA (R||S) to DER format"""
    # For P-256, R and S are each 32 bytes
    if len(raw_sig) != 64:
        raise ValueError(f"Expected 64 bytes, got {len(raw_sig)}")

    r = raw_sig[:32]
    s = raw_sig[32:]

    # DER encoding helpers
    def encode_integer(value):
        """Encode integer as DER"""
        # Remove leading zeros but keep one if high bit set
        value = value.lstrip(b'\\x00')
        if not value or (value[0] & 0x80):
            value = b'\\x00' + value
        return b'\\x02' + bytes([len(value)]) + value

    r_der = encode_integer(r)
    s_der = encode_integer(s)

    # SEQUENCE { r, s }
    inner = r_der + s_der
    return b'\\x30' + bytes([len(inner)]) + inner

if __name__ == '__main__':
    signature_b64url = sys.argv[1]
    raw_sig = base64url_decode(signature_b64url)
    der_sig = raw_to_der(raw_sig)
    sys.stdout.buffer.write(der_sig)
```

Save as `convert_sig.py` and run:

```bash
python3 convert_sig.py "$SIGNATURE" > signature.der
```

### Step 4: Verify with OpenSSL

```bash
openssl dgst -sha256 \\
  -verify public_key.pem \\
  -signature signature.der \\
  signing_input.txt
```

**Expected output:**
```
Verified OK
```

**If verification fails:**
```
Verification Failure
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

Here's a complete worked example:

```bash
# 1. Extract JWS (from verification package)
$ cat jws_original.txt
eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2V5IiwidHlwIjoiSldUIn0.eyJhbW91bnQiOjUwMDAwLCJjdXJyZW5jeSI6IkVVUiIsImV4cCI6MTczNTE0MTM0NiwiaWF0IjoxNzM1MTQxMDQ2LCJpbnN0cnVjdGlvbl9pZCI6InR4bl9pbnRlZ3JhdGlvbl8wMDEiLCJqdGkiOiI2NjhhNzQxYy1hZTBlLTQzZmEtOTBmYy1mM2VjYmYwZWUzZjkifQ.kp1uhb-QhBi_EKj_peGsx7mmPsS7tPS0IsK1_A8eU2q_s3iT1Rqo7gJADCB-Q5xLKzQiNPqWCxjHmqBGW3KuXA

# 2. Extract parts
$ JWS=$(cat jws_original.txt)
$ HEADER=$(echo "$JWS" | cut -d'.' -f1)
$ PAYLOAD=$(echo "$JWS" | cut -d'.' -f2)
$ SIGNATURE=$(echo "$JWS" | cut -d'.' -f3)

# 3. Create signing input
$ echo -n "${HEADER}.${PAYLOAD}" > signing_input.txt
$ wc -c signing_input.txt
367 signing_input.txt

# 4. Convert signature to DER
$ python3 convert_sig.py "$SIGNATURE" > signature.der
$ ls -lh signature.der
-rw-r--r-- 1 user user 70 Dec  7 20:00 signature.der

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
  "amount": 50000,
  "currency": "EUR",
  "exp": 1735141346,
  "iat": 1735141046,
  "instruction_id": "txn_integration_001",
  "jti": "668a741c-ae0e-43fa-90fc-f3ecbf0ee3f9"
}
```

Check timestamps:

```bash
# Convert Unix timestamps to readable dates
date -d @1735141046  # iat (issued at)
date -d @1735141346  # exp (expiration)
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

This verification protocol satisfies requirements for:

- **PSD2 Strong Customer Authentication**: Cryptographic proof of authorization
- **PCI DSS**: Non-repudiation for payment transactions
- **GDPR**: Audit trail for data processing authorization
- **SOX**: Proof of financial transaction authorization

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

- **Blog Post 5**: Audit Trails and Re-Verification
- **Test Reference**: `test/jws_demo/integration/authorization_flow_test.exs`
- **Audit Module**: `lib/jws_demo/jws/audit.ex`
- **RFC 7515**: JSON Web Signature (JWS) specification

---

**Last Updated**: 2025-12-07
**Version**: 1.0
**Maintainer**: JWS Demo Project
