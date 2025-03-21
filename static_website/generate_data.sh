#!/bin/bash

# Directory containing the IP list configuration files
IPLIST_DIR="$1"
OUTPUT_DIR="$2"

# Function to process a JSON file and extract CIDR blocks
extract_cidrs() {
    local json_file="$1"
    local output_file="$2"
    
    # Extract cidr4 blocks using grep and basic JSON parsing
    grep -o '"cidr4": \[[^]]*\]' "$json_file" | 
        sed 's/"cidr4": \[\(.*\)\]/\1/' | 
        tr -d ' "' > "$output_file"
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Find all category directories
find "$IPLIST_DIR/config" -mindepth 1 -maxdepth 1 -type d | while read category_path; do
    category=$(basename "$category_path")
    
    # Skip hidden directories
    if [[ "$category" == .* ]]; then
        continue
    fi
    
    # Create category directory in output
    mkdir -p "$OUTPUT_DIR/$category"
    
    # Process each service JSON file in the category
    find "$category_path" -name "*.json" | while read service_path; do
        service_file=$(basename "$service_path")
        service_name="${service_file%.json}"
        
        # Skip if service name starts with a dot
        if [[ "$service_name" == .* ]]; then
            continue
        fi
        
        # Extract CIDR blocks to a temporary file
        extract_cidrs "$service_path" "$OUTPUT_DIR/$category/$service_name.txt"
    done
done

echo "CIDR extraction complete. Files saved to $OUTPUT_DIR"