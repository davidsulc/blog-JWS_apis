# JWS Verification Package

## Authorization Details

- **Instruction ID:** txn_integration_001
- **Verified At:** 2025-12-16 17:56:32Z
- **Algorithm:** ES256
- **Key ID:** N/A

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
   openssl dgst -sha256 -verify public_key.pem \
     -signature signature.der signing_input.txt
   ```

   Expected output: `Verified OK`

## What This Proves

A successful verification proves:
1. The partner's private key holder signed this exact payload
2. The payload has not been modified since signing
3. The signature was created with the specified algorithm (ES256)
4. The partner cannot credibly deny authorizing this transaction

This is cryptographic non-repudiation.

## Payload Contents

```json
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

---

Generated: 2025-12-16T17:56:32.713466Z
