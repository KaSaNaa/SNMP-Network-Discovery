#!/bin/bash
# Discover devices from a list of IP addresses
# Usage: ./discover_from_list.sh ip_list.txt public

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <ip_list_file> <community>"
    echo "Example: $0 ip_list.txt public"
    exit 1
fi

IP_LIST=$1
COMMUNITY=$2

if [ ! -f "$IP_LIST" ]; then
    echo "Error: File $IP_LIST not found"
    exit 1
fi

# Create output directory
OUTPUT_DIR="discovery_results/list_scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "Starting SNMP discovery from $IP_LIST"
echo "Community: $COMMUNITY"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

discovered=0
failed=0
total=0

while IFS= read -r IP || [ -n "$IP" ]; do
    # Skip empty lines and comments
    [[ -z "$IP" || "$IP" =~ ^#.*  ]] && continue
    
    ((total++))
    OUTPUT_FILE="$OUTPUT_DIR/${IP//\./_}.json"
    
    echo -n "Scanning $IP... "
    
    # Run discovery with timeout
    timeout 180 python main.py "$IP" --community "$COMMUNITY" > "$OUTPUT_FILE" 2>&1
    
    # Check if successful
    if grep -q '"Device Name"' "$OUTPUT_FILE" 2>/dev/null; then
        DEVICE_NAME=$(grep '"Device Name"' "$OUTPUT_FILE" | cut -d'"' -f4)
        DEVICE_TYPE=$(grep '"Device type"' "$OUTPUT_FILE" | cut -d'"' -f4)
        echo "✓ $DEVICE_TYPE - $DEVICE_NAME"
        ((discovered++))
    else
        echo "✗ No response"
        rm "$OUTPUT_FILE"
        ((failed++))
    fi
    
    sleep 0.5
done < "$IP_LIST"

echo ""
echo "================================"
echo "Discovery Summary"
echo "================================"
echo "Total IPs scanned: $total"
echo "Devices discovered: $discovered"
echo "Failed/No response: $failed"
echo "Results saved in: $OUTPUT_DIR"
