#!/bin/bash
# Discover multiple devices in a subnet range
# Usage: ./discover_subnet.sh 192.168.1 1 254 public

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <subnet> <start> <end> <community>"
    echo "Example: $0 192.168.1 1 254 public"
    exit 1
fi

SUBNET=$1
START=$2
END=$3
COMMUNITY=$4

# Create output directory
mkdir -p discovery_results
OUTPUT_DIR="discovery_results/scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "Starting SNMP discovery for $SUBNET.$START-$END"
echo "Community: $COMMUNITY"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

discovered=0
failed=0

for i in $(seq $START $END); do
    IP="$SUBNET.$i"
    OUTPUT_FILE="$OUTPUT_DIR/${IP//\./_}.json"
    
    echo -n "Scanning $IP... "
    
    # Run discovery with timeout
    timeout 180 python main.py "$IP" --community "$COMMUNITY" > "$OUTPUT_FILE" 2>&1
    
    # Check if successful
    if grep -q '"Device Name"' "$OUTPUT_FILE" 2>/dev/null; then
        DEVICE_NAME=$(grep '"Device Name"' "$OUTPUT_FILE" | cut -d'"' -f4)
        DEVICE_TYPE=$(grep '"Device type"' "$OUTPUT_FILE" | cut -d'"' -f4)
        echo "✓ Found: $DEVICE_TYPE - $DEVICE_NAME"
        ((discovered++))
    else
        echo "✗ No response"
        rm "$OUTPUT_FILE"  # Remove failed attempts
        ((failed++))
    fi
    
    # Add small delay to avoid overwhelming the network
    sleep 0.5
done

echo ""
echo "================================"
echo "Discovery Summary"
echo "================================"
echo "Total IPs scanned: $((END - START + 1))"
echo "Devices discovered: $discovered"
echo "Failed/No response: $failed"
echo "Results saved in: $OUTPUT_DIR"
echo ""
echo "To view all discovered devices:"
echo "  cat $OUTPUT_DIR/*.json | jq '.\"Device Name\", .\"Device type\", .\"IP Address\"'"
