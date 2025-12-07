#!/bin/bash
# Generate ES256 (ECDSA P-256) key pairs for demo
#
# Usage: ./scripts/generate_keys.sh

set -e

KEYS_DIR="priv/keys"

echo "Generating ES256 keypairs for JWS demo..."
echo

# Create keys directory if it doesn't exist
mkdir -p "$KEYS_DIR"

# Generate demo server keys (our keys for signing)
echo "1. Generating demo server keypair..."
openssl ecparam -name prime256v1 -genkey -noout -out "$KEYS_DIR/demo_private_key.pem"
openssl ec -in "$KEYS_DIR/demo_private_key.pem" -pubout -out "$KEYS_DIR/demo_public_key.pem"
echo "   ✓ Created demo_private_key.pem and demo_public_key.pem"

# Generate partner ABC keys (for testing partner signatures)
echo "2. Generating partner ABC keypair..."
openssl ecparam -name prime256v1 -genkey -noout -out "$KEYS_DIR/partner_abc_private.pem"
openssl ec -in "$KEYS_DIR/partner_abc_private.pem" -pubout -out "$KEYS_DIR/partner_abc_public.pem"
echo "   ✓ Created partner_abc_private.pem and partner_abc_public.pem"

echo
echo "✓ All keys generated successfully in $KEYS_DIR/"
echo
echo "Next steps:"
echo "  - Use demo keys for publishing JWKS endpoint"
echo "  - Use partner keys for simulating partner requests in tests"
echo "  - Run 'mix test' to verify signing/verification works"
