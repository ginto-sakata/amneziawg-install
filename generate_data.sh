#!/bin/bash

# Directory containing the IP list configuration files

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IPLIST_CONFIG_DIR="$SCRIPT_DIR/iplist/config"
OUTPUT_DIR="$SCRIPT_DIR/static_website"
SERVICES_FILE="$SCRIPT_DIR/static_website/services.json" # Not directly used for categories anymore

echo "Generating data from $IPLIST_CONFIG_DIR to $OUTPUT_DIR..."
echo "services file: $SERVICES_FILE" # Still echoing for info

# Check if required files exist (services.json might still be used later)
if [ ! -f "$SERVICES_FILE" ]; then
    echo "Warning: services.json not found, but proceeding as categories are folder-based."
fi

# Check if jq is available
if command -v jq &> /dev/null; then
    echo "Using jq for JSON processing"
    HAS_JQ=1
else
    echo "Error: jq is required for this script"
    echo "Install jq: jq (sudo apt install jq)"
    exit 1
fi

# Create initial JSON structure
cat > "$OUTPUT_DIR/cidrs.json" << EOF
{
  "services": {
  }
}
EOF

# Get service categories from directory structure
echo "Loading service categories from directories..."
SERVICE_CATEGORIES_ARRAY=($(find "$IPLIST_CONFIG_DIR" -maxdepth 1 -type d -not -path "$IPLIST_CONFIG_DIR" -printf "%f\n")) # Get folder names

# --- Formatting Variables for Log Output ---
RESET_COLOR="\033[0m"
BOLD_GREEN="\033[1;32m"
BOLD_CYAN="\033[1;36m"

# Process service categories and services - Simple Scrolling Log Output
echo "Processing service categories - SIMPLE SCROLLING LOG OUTPUT..."

# Process each service file in the config directory - now iterating by category and service from directories
for category_name in "${SERVICE_CATEGORIES_ARRAY[@]}"; do
    echo -e "\n${BOLD_GREEN}--- Category: ${category_name} ---${RESET_COLOR}" # Nice Category Header

    # Get services for this category by listing files in the category directory
    SERVICES_IN_CATEGORY_ARRAY=($(find "$IPLIST_CONFIG_DIR/$category_name" -maxdepth 1 -name "*.json" -type f -printf "%f\n" | sed 's/\.json$//'))
    for service_id in "${SERVICES_IN_CATEGORY_ARRAY[@]}"; do
        service_file="$IPLIST_CONFIG_DIR/$category_name/${service_id}.json" # Construct FULL service file path (including category)

        echo -e "${BOLD_CYAN}  Processing service: ${service_id}${RESET_COLOR}" # Nice Service Processing Log

        if [ -f "$service_file" ]; then # Check if file exists (important!)
            # No more whitelist check against services.json categories - directory structure IS the whitelist

            # Extract CIDRs from service file
            cidrs=$(jq -c '.cidr4 // []' "$service_file")

            # Skip if no CIDRs
            if [ "$cidrs" = "[]" ] || [ -z "$cidrs" ]; then
                echo "    No CIDRs found, skipping"
                continue
            fi

            # Add service to JSON with CIDRs
            jq --arg id "$service_id" \
               --argjson cidrs "$cidrs" \
               '.services[$id] = {"cidrs": $cidrs}' \
               "$OUTPUT_DIR/cidrs.json" > "$OUTPUT_DIR/cidrs.json.tmp"
            mv "$OUTPUT_DIR/cidrs.json.tmp" "$OUTPUT_DIR/cidrs.json"
        else
            echo "    Warning: Service file not found: $service_file" # Warning if file missing
        fi
    done
done

echo -e "\n${BOLD_GREEN}Data generation complete. File saved to: $OUTPUT_DIR${RESET_COLOR}" # Formatted Completion Message
echo -e "${BOLD_GREEN}  - cidrs.json${RESET_COLOR}" # Formatted File Output Message


# Move cursor down after processing to avoid overwriting terminal input - Not really needed in scrolling output, but kept for consistency
echo -e "\n\n"