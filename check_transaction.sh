#!/bin/bash

# Quick script to check if a transaction has MessageDispatched event
# Usage: ./check_transaction.sh <tx_hash>

TX_HASH="${1:-0xee78b18d0af464e73947a50f864268f48cb8b01fa99eb6723c9a60b953bd8e48}"
HANDLER_V1="0x4638945E120846366cB7Abc08DB9c0766E3a663F"
EVENT_SIG="0x0a0607688c86ec1775abcdbab7b33a3a35a6c9cde677c9be880150c231cc6b0b"

echo "🔍 Checking transaction: $TX_HASH"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Query Base Sepolia RPC
curl -s -X POST https://sepolia.base.org \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\":\"2.0\",
    \"method\":\"eth_getTransactionReceipt\",
    \"params\":[\"$TX_HASH\"],
    \"id\":1
  }" | jq -r "
    if .result.logs then
      .result.logs[] | 
      select(.address | ascii_downcase == \"${HANDLER_V1,,}\") |
      select(.topics[0] == \"$EVENT_SIG\") |
      \"✅ MessageDispatched Event Found!\n\" +
      \"   Contract: \(.address)\n\" +
      \"   Event Signature: \(.topics[0])\n\" +
      \"   Commitment: \(.topics[1])\"
    else
      \"❌ No MessageDispatched event found in this transaction\"
    end
  "

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

