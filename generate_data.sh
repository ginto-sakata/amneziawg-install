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
SERVICE_IDS_JSON=$(jq -r 'keys' "$SERVICES_FILE") # Get keys as JSON array
SERVICE_IDS_ARRAY=($(jq -r '.[]' <<< "$SERVICE_IDS_JSON")) # Convert JSON array to bash array

# Process each service file in the config directory
echo "Processing service files..."
rows=20        # Set number of rows per column
col_width=15   # Width of each column (adjust if needed)
num_services=${#SERVICE_IDS_ARRAY[@]}
num_cols=$(( (num_services + rows - 1) / rows )) # Calculate required columns

# Loop through rows, then columns to print in desired order
for row_index in $(seq 0 $((rows - 1))); do
    for col_index in $(seq 0 $((num_cols - 1))); do
        service_index=$((row_index + col_index * rows))

        if [ "$service_index" -lt "$num_services" ]; then
            service_id="${SERVICE_IDS_ARRAY[$service_index]}"
            col_offset=$((col_index * col_width))
            printf "%${col_offset}s%-${col_width}s" "" "$service_id"
        else
            # If no more services for this position, print spacing
            col_offset=$((col_index * col_width))
            printf "%${col_offset}s%-${col_width}s" "" "" # Print spaces
        fi
    done
    echo "" # Newline after each row
done

# Move cursor down after processing to avoid overwriting terminal input
echo -e "\n\n"


    # ... (rest of your script for CIDR processing - unchanged) ...

    find "$IPLIST_CONFIG_DIR" -name "*.json" -type f | while read -r service_file; do
        service_id=$(basename "$service_file" .json)

        if ! echo "$SERVICE_IDS_JSON" | jq -e 'contains(["'$service_id'"])'; then # Use jq for array check
            continue
        fi

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