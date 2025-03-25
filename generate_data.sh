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

# --- Layout Variables (Extreme Compactness & Debugging) ---
rows=10        # Further reduced rows for very tall, narrow columns
cols_per_row=4 # Number of columns per output row
col_separator=" | " # Very distinct column separator (pipe with spaces)
col_width=5      # Setting col_width to a very small value (though not directly used now)

num_categories=${#SERVICE_CATEGORIES_ARRAY[@]}
num_output_rows=$(( (num_categories + cols_per_row - 1) / cols_per_row )) # Number of output rows needed

output_row_index=0 # Counter for output rows

# Process service categories and services - EXTREME COMPACT OUTPUT
echo "Processing service categories - EXTREME COMPACT OUTPUT..."

# Loop through output rows (sets of columns)
for output_row in $(seq 1 $((num_output_rows))); do

    # Print category headers for this row
    echo -n "Headers: " # Debugging prefix for headers
    for col_index_header in $(seq 0 $((cols_per_row - 1))); do
        category_index_header=$((output_row_index * cols_per_row + col_index_header))
        if [ "$category_index_header" -lt "$num_categories" ]; then
            category_name="${SERVICE_CATEGORIES_ARRAY[$category_index_header]}"
            printf "%s%s" "$category_name" "$col_separator" # Category Header + Separator
        else
            printf "%s%s" "" "$col_separator" # Separator if no category
        fi
    done
    echo "" # Newline after category headers

    # Print service IDs under each category for this row
    echo -n "Services: " # Debugging prefix for services
    for row_index in $(seq 0 $((rows - 1))); do
        echo -n "  Row $row_index: " # Debugging row number
        for col_index_services in $(seq 0 $((cols_per_row - 1))); do
            category_index_services=$((output_row_index * cols_per_row + col_index_services))
            if [ "$category_index_services" -lt "$num_categories" ]; then
                category_name="${SERVICE_CATEGORIES_ARRAY[$category_index_services]}"
                # Get services for this category by listing files in the category directory
                SERVICES_IN_CATEGORY_ARRAY=($(find "$IPLIST_CONFIG_DIR/$category_name" -maxdepth 1 -name "*.json" -type f -printf "%f\n" | sed 's/\.json$//'))

                service_index=$row_index # Row index is the service index within category
                if [ "$service_index" -lt "${#SERVICES_IN_CATEGORY_ARRAY[@]}" ]; then
                    service_id="${SERVICES_IN_CATEGORY_ARRAY[$service_index]}"
                    printf "%s%s" "$service_id" "$col_separator" # Service ID + Separator
                else
                    printf "%s%s" "" "$col_separator" # Separator if no service
                fi
            else
                printf "%s%s" "" "$col_separator" # Separator if no category
            fi
        done
        echo "" # Newline after each row of services
    done

    output_row_index=$((output_row_index + 1)) # Move to next output row
    echo ""  # Add an extra newline to separate output rows visually
done


# Move cursor down after processing to avoid overwriting terminal input
echo -e "\n\n"


# --- CIDR Processing Section (Full and Corrected - No Changes Here) ---

echo "Processing CIDR data for each service..."

# Process each service file in the config directory - now iterating by category and service from directories
for category_name in "${SERVICE_CATEGORIES_ARRAY[@]}"; do
    # Get services for this category by listing files in the category directory
    SERVICES_IN_CATEGORY_ARRAY=($(find "$IPLIST_CONFIG_DIR/$category_name" -maxdepth 1 -name "*.json" -type f -printf "%f\n" | sed 's/\.json$//'))
    for service_id in "${SERVICES_IN_CATEGORY_ARRAY[@]}"; do

        service_file="$IPLIST_CONFIG_DIR/$category_name/${service_id}.json" # Construct FULL service file path (including category)

        if [ -f "$service_file" ]; then # Check if file exists (important!)

            # No more whitelist check against services.json categories - directory structure IS the whitelist

            # Extract CIDRs from service file
            cidrs=$(jq -c '.cidr4 // []' "$service_file")

            # Skip if no CIDRs
            if [ "$cidrs" = "[]" ] || [ -z "$cidrs" ]; then
                echo "  No CIDRs found for $service_id in category $category_name, skipping"
                continue
            fi

            # Add service to JSON with CIDRs
            jq --arg id "$service_id" \
               --argjson cidrs "$cidrs" \
               '.services[$id] = {"cidrs": $cidrs}' \
               "$OUTPUT_DIR/cidrs.json" > "$OUTPUT_DIR/cidrs.json.tmp"
            mv "$OUTPUT_DIR/cidrs.json.tmp" "$OUTPUT_DIR/cidrs.json"
        else
            echo "Warning: Service file not found: $service_file" # Warning if file missing
        fi
    done
done


echo "Data generation complete. File saved to: $OUTPUT_DIR"
echo "  - cidrs.json"