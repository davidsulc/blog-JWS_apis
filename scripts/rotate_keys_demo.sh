#!/bin/bash
#
# Key Rotation Demo Script
#
# Demonstrates zero-downtime key rotation for JWKS endpoint.
#
# The rotation process has 3 phases:
# 1. Current state: Single active key
# 2. Transition: Add new key (both keys valid)
# 3. Final state: Remove old key (only new key)
#
# During phase 2, signatures from BOTH keys are valid, enabling
# zero-downtime rotation.

set -e

JWKS_URL="http://localhost:4000/.well-known/jwks.json"
API_URL="http://localhost:4000"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== JWS Key Rotation Demo ===${NC}\n"

# Check if server is running
if ! curl -s -f "$JWKS_URL" > /dev/null 2>&1; then
  echo -e "${YELLOW}⚠️  Server not running at $API_URL${NC}"
  echo "Please start the server with: mix phx.server"
  exit 1
fi

echo -e "${GREEN}✓ Server is running${NC}\n"

# Phase 1: Show current JWKS
echo -e "${BLUE}=== Phase 1: Current JWKS State ===${NC}"
echo "Fetching $JWKS_URL"
echo ""

CURRENT_KEYS=$(curl -s "$JWKS_URL" | jq -r '.keys | length')
echo -e "Active keys: ${GREEN}$CURRENT_KEYS${NC}"
curl -s "$JWKS_URL" | jq '.keys[] | {kid: .kid, alg: .alg, use: .use}'
echo ""

# Phase 2: Add new key
echo -e "${BLUE}=== Phase 2: Add New Key (Zero-Downtime Transition) ===${NC}"
echo "Adding rotation key to JWKS..."
echo ""

# Generate new key
echo "Generating new ES256 key pair..."
NEW_KEY_ID="demo-$(date +%Y-%m)-rotated"
openssl ecparam -name prime256v1 -genkey -noout -out "/tmp/${NEW_KEY_ID}_private.pem" 2>/dev/null
openssl ec -in "/tmp/${NEW_KEY_ID}_private.pem" -pubout -out "/tmp/${NEW_KEY_ID}_public.pem" 2>/dev/null

echo -e "${GREEN}✓ New key generated: $NEW_KEY_ID${NC}"
echo ""

# Add key to database (demo approach - in production this would be via admin API)
echo "In production, you would:"
echo "  1. Generate new key in KMS/HSM"
echo "  2. Add to JWKS via admin endpoint"
echo "  3. Wait for cache refresh (15 minutes)"
echo ""

echo -e "${YELLOW}Demo: Both old and new keys now valid${NC}"
echo "Partners can use either key during transition period"
echo ""

# Show JWKS with both keys (simulated)
echo "JWKS would now contain:"
echo '{"keys": [
  {"kid": "demo-2025-01", "alg": "ES256", "use": "sig", ...},
  {"kid": "'$NEW_KEY_ID'", "alg": "ES256", "use": "sig", ...}
]}'
echo ""

# Phase 3: Remove old key
echo -e "${BLUE}=== Phase 3: Remove Old Key (Complete Rotation) ===${NC}"
echo "After grace period (typically 24-48 hours):"
echo "  1. Verify all partners using new key"
echo "  2. Check audit logs for old key usage"
echo "  3. Remove old key from JWKS"
echo ""

echo "JWKS would then contain only:"
echo '{"keys": [
  {"kid": "'$NEW_KEY_ID'", "alg": "ES256", "use": "sig", ...}
]}'
echo ""

# Cleanup
rm -f "/tmp/${NEW_KEY_ID}_private.pem" "/tmp/${NEW_KEY_ID}_public.pem"

# Best Practices
echo -e "${BLUE}=== Key Rotation Best Practices ===${NC}"
echo ""
echo "✓ Rotation frequency: Every 90 days"
echo "✓ Grace period: 24-48 hours with both keys active"
echo "✓ Monitor audit logs: Track old key usage"
echo "✓ Cache invalidation: Force refresh after adding new key"
echo "✓ Partner notification: Announce rotation 1 week ahead"
echo "✓ Emergency rotation: Can be done in minutes if compromised"
echo ""

echo -e "${GREEN}=== Demo Complete ===${NC}"
echo ""
echo "Key rotation enables:"
echo "  - Zero downtime during rotation"
echo "  - Gradual partner migration"
echo "  - Emergency key revocation"
echo "  - Regular cryptographic hygiene"
echo ""

echo "See README.md for more on key management and rotation."
