#!/bin/bash

# Directory containing the IP list configuration files

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IPLIST_CONFIG_DIR="$SCRIPT_DIR/iplist/config"
OUTPUT_DIR="$SCRIPT_DIR/static_website"
SERVICES_FILE="$SCRIPT_DIR/static_website/services.json"


echo "Generating data from $IPLIST_CONFIG_DIR to $OUTPUT_DIR..."
echo "services file: $SERVICES_FILE"

# Check if required files exist
if [ ! -f "$SERVICES_FILE" ]; then
    echo "Error: services.json not found"
    exit 1
fi

# Check if jq is available
if command -v jq &> /dev/null; then
    echo "Using jq for JSON processing"
    HAS_JQ=1
else
    echo "Error: jq is required for this script"
    echo "Install jq: apt-get install jq"
    exit 1
fi

# Create initial JSON structure
cat > "$OUTPUT_DIR/cidrs.json" << EOF
{
  "services": {
  }
}
EOF

# First, get all service IDs from services.json (this is our whitelist)
echo "Loading service whitelist..."
SERVICE_IDS=$(jq -r 'keys[]' "$SERVICES_FILE")

# Process each service file in the config directory
echo "Processing service files..."
columns=3      # Set number of columns
rows=20        # Set number of rows per column
counter=0      # Keeps track of the printed service index

find "$IPLIST_CONFIG_DIR" -name "*.json" -type f | while read -r service_file; do
    service_id=$(basename "$service_file" .json)
    
    if ! echo "$SERVICE_IDS" | grep -q "^$service_id$"; then
        continue
    fi

    row=$((counter % rows))
    col=$((counter / rows))

    # Move cursor to correct position
    printf "\033[%d;%dH%-25s" $((row + 2)) $((col * 26 + 1)) "$service_id"

    counter=$((counter + 1))
done

# Move cursor down after processing to avoid overwriting terminal input
echo -e "\n\n"


    
    # Extract CIDRs from service file
    cidrs=$(jq -c '.cidr4 // []' "$service_file")
    
    # Skip if no CIDRs
    if [ "$cidrs" = "[]" ] || [ -z "$cidrs" ]; then
        echo "  No CIDRs found, skipping"
        continue
    fi
    
    # Add service to JSON with CIDRs only
    jq --arg id "$service_id" \
       --argjson cidrs "$cidrs" \
       '.services[$id] = {"cidrs": $cidrs}' \
       "$OUTPUT_DIR/cidrs.json" > "$OUTPUT_DIR/cidrs.json.tmp"
    mv "$OUTPUT_DIR/cidrs.json.tmp" "$OUTPUT_DIR/cidrs.json"
done


echo "Data generation complete. File saved to: $OUTPUT_DIR"
echo "  - cidrs.json"
