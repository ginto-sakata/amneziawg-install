#!/bin/bash

# Directory containing the IP list configuration files
CONFIG_DIR="${1:-./iplist/config}"
OUTPUT_DIR="${2:-./static_website}"
SERVICES_FILE="${3:-./services.json}"

echo "Generating data from $CONFIG_DIR to $OUTPUT_DIR..."

# First, ensure we have the iplist repository
echo "Ensuring iplist repository is available..."
chmod +x clone_iplist.sh
./clone_iplist.sh

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

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
    
    # Add service to JSON with CIDRs only
    jq --arg id "$service_id" \
       --argjson cidrs "$cidrs" \
       '.services[$id] = {"cidrs": $cidrs}' \
       "$OUTPUT_DIR/cidrs.json" > "$OUTPUT_DIR/cidrs.json.tmp"
    mv "$OUTPUT_DIR/cidrs.json.tmp" "$OUTPUT_DIR/cidrs.json"
done

# Copy required JSON files to static_website directory
echo "Copying required JSON files to $OUTPUT_DIR..."
cp services.json "$OUTPUT_DIR/"
cp categories.json "$OUTPUT_DIR/"
cp descriptions.json "$OUTPUT_DIR/"

echo "Data generation complete. Files saved to: $OUTPUT_DIR"
echo "  - cidrs.json"
echo "  - services.json"
echo "  - categories.json"
echo "  - descriptions.json"