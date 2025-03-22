#!/bin/bash

# Directory containing the IP list configuration files
CONFIG_DIR="${1:-./iplist/config}"
OUTPUT_FILE="${2:-./static_website/data.json}"
DESCRIPTIONS_FILE="${3:-./descriptions.json}"
SERVICES_FILE="${4:-./services.json}"
CATEGORIES_FILE="${5:-./categories.json}"

echo "Generating data from $CONFIG_DIR to $OUTPUT_FILE..."

# Ensure output directory exists
mkdir -p $(dirname "$OUTPUT_FILE")

# Check if required files exist
if [ ! -f "$DESCRIPTIONS_FILE" ]; then
    echo "Error: descriptions.json not found"
    exit 1
fi

if [ ! -f "$SERVICES_FILE" ]; then
    echo "Error: services.json not found"
    exit 1
fi

if [ ! -f "$CATEGORIES_FILE" ]; then
    echo "Error: categories.json not found"
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
cat > "$OUTPUT_FILE" << EOF
{
  "categories": {
  }
}
EOF

# Process each category from categories.json
jq -r '.categories | to_entries[] | .key as $cat | .value.services[] | [$cat, .]' "$CATEGORIES_FILE" | while read -r category service_id; do
    # Find the service file in the config directory
    service_file=$(find "$CONFIG_DIR" -name "${service_id}.json" -type f)
    
    if [ -n "$service_file" ]; then
        echo "Processing service: $service_id in category: $category"
        
        # Extract CIDRs from service file
        cidrs=$(jq -c '.cidr4 // []' "$service_file")
        
        # Skip if no CIDRs
        if [ "$cidrs" = "[]" ] || [ -z "$cidrs" ]; then
            echo "  No CIDRs found, skipping"
            continue
        fi
        
        # Add service to JSON
        jq --arg cat "$category" \
           --arg id "$service_id" \
           --arg url "https://$service_id" \
           --argjson cidrs "$cidrs" \
           '.categories[$cat].services[$id] = {"url": $url, "cidrs": $cidrs}' \
           "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
        mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    else
        echo "Warning: Service file not found for $service_id"
    fi
done

echo "Data generation complete. File saved to: $OUTPUT_FILE"