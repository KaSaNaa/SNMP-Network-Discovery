#!/bin/bash
# Discover devices using SNMPv3
# Usage: ./discover_snmpv3.sh <ip> <user> <auth_key> <priv_key>

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <ip> <user> <auth_key> <priv_key>"
    echo "Example: $0 192.168.1.1 admin Auth123! Priv456!"
    exit 1
fi

IP=$1
USER=$2
AUTH_KEY=$3
PRIV_KEY=$4

# Default protocols
AUTH_PROTO="SHA"
PRIV_PROTO="AES"

# Create output directory
OUTPUT_DIR="discovery_results"
mkdir -p "$OUTPUT_DIR"

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

OUTPUT_FILE="$OUTPUT_DIR/${IP//\./_}_v3.json"

echo "Starting SNMPv3 discovery for $IP"
echo "User: $USER"
echo "Auth Protocol: $AUTH_PROTO"
echo "Privacy Protocol: $PRIV_PROTO"
echo ""

# Run discovery
python main.py "$IP" \
    --version 3 \
    --user "$USER" \
    --auth_key "$AUTH_KEY" \
    --priv_key "$PRIV_KEY" \
    --auth_proto "$AUTH_PROTO" \
    --priv_proto "$PRIV_PROTO" > "$OUTPUT_FILE"

# Check result
if grep -q '"Device Name"' "$OUTPUT_FILE" 2>/dev/null; then
    echo "✓ Discovery successful!"
    echo ""
    cat "$OUTPUT_FILE" | jq '{
        "Device Name", 
        "Device type", 
        "IP Address", 
        "Manufacturer",
        "System OID"
    }'
    echo ""
    echo "Full results saved to: $OUTPUT_FILE"
else
    echo "✗ Discovery failed"
    echo "Check logs/snmp_errors.log for details"
    cat "$OUTPUT_FILE"
fi
