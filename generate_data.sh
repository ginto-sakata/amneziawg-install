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

# First, get all service IDs from services.json (this is our whitelist)
echo "Loading service whitelist..."
SERVICE_IDS=$(jq -r 'keys[]' "$SERVICES_FILE")

# Process each service file in the config directory
echo "Processing service files..."
find "$CONFIG_DIR" -name "*.json" -type f | while read -r service_file; do
    # Get service ID from filename
    service_id=$(basename "$service_file" .json)
    
    # Skip if service is not in our whitelist
    if ! echo "$SERVICE_IDS" | grep -q "^$service_id$"; then
        echo "Skipping unknown service: $service_id"
        continue
    fi
    
    echo "Processing service: $service_id"
    
    # Extract CIDRs from service file
    cidrs=$(jq -c '.cidr4 // []' "$service_file")
    
    # Skip if no CIDRs
    if [ "$cidrs" = "[]" ] || [ -z "$cidrs" ]; then
        echo "  No CIDRs found, skipping"
        continue
    fi
    
    # Find which category this service belongs to
    category=$(jq -r --arg id "$service_id" '.categories | to_entries[] | select(.value.services[] | contains($id)) | .key' "$CATEGORIES_FILE")
    
    if [ -n "$category" ]; then
        echo "  Found in category: $category"
        
        # Add service to JSON with CIDRs only
        jq --arg cat "$category" \
           --arg id "$service_id" \
           --argjson cidrs "$cidrs" \
           '.categories[$cat].services[$id] = {"cidrs": $cidrs}' \
           "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
        mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    else
        echo "  Warning: Service not found in any category"
    fi
done

echo "Data generation complete. File saved to: $OUTPUT_FILE"