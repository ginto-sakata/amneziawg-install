#!/bin/bash

# Directory containing the IP list configuration files
IPLIST_DIR="$1"
OUTPUT_DIR="$2"

# Function to process a JSON file and extract CIDR blocks
extract_cidrs() {
    local json_file="$1"
    local output_file="$2"
    
    # Extract cidr4 blocks using jq if available, or grep as fallback
    if command -v jq &> /dev/null; then
        jq -r '.cidr4[]' "$json_file" > "$output_file" 2>/dev/null
    else
        # Extract cidr4 blocks using grep and basic JSON parsing
        grep -o '"cidr4": \[[^]]*\]' "$json_file" | 
            sed 's/"cidr4": \[\(.*\)\]/\1/' | 
            tr -d ' "' | tr ',' '\n' > "$output_file" 2>/dev/null
    fi
}

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Initialize the JSON structure
echo '{
    "categories": {}
}' > "$OUTPUT_DIR/data.json.tmp"

# Find all category directories
find "$IPLIST_DIR/config" -mindepth 1 -maxdepth 1 -type d | while read category_path; do
    category=$(basename "$category_path")
    
    # Skip hidden directories
    if [[ "$category" == .* ]]; then
        continue
    fi
    
    # Create category directory in output
    mkdir -p "$OUTPUT_DIR/$category"
    
    # Add category to JSON structure
    if command -v jq &> /dev/null; then
        jq --arg category "$category" '.categories[$category] = {"services": {}}' "$OUTPUT_DIR/data.json.tmp" > "$OUTPUT_DIR/data.json.tmp2"
        mv "$OUTPUT_DIR/data.json.tmp2" "$OUTPUT_DIR/data.json.tmp"
    else
        # Fallback without jq (less reliable)
        sed -i "s/\"categories\": {/\"categories\": {\"$category\": {\"services\": {}},/g" "$OUTPUT_DIR/data.json.tmp"
    fi
    
    # Process each service JSON file in the category
    find "$category_path" -name "*.json" | while read service_path; do
        service_file=$(basename "$service_path")
        service_name="${service_file%.json}"
        
        # Skip if service name starts with a dot
        if [[ "$service_name" == .* ]]; then
            continue
        fi
        
        # Create a better display name from service name
        display_name=$(echo "$service_name" | sed -E 's/\./-/g' | sed -E 's/(^|-)([a-z])/\U\2/g')
        
        # Extract main domain from the service file
        main_domain=""
        if command -v jq &> /dev/null; then
            main_domain=$(jq -r '.domains[0]' "$service_path" 2>/dev/null)
        else
            main_domain=$(grep -o '"domains": \[[^]]*\]' "$service_path" | sed 's/"domains": \[\([^,]*\).*/\1/' | tr -d ' "')
        fi
        
        # If main_domain is empty or null, use service_name as fallback
        if [[ -z "$main_domain" || "$main_domain" == "null" ]]; then
            main_domain="$service_name"
        fi
        
        # Prepare the service URL
        service_url="https://$main_domain"
        
        # Extract description (placeholder for now)
        description="Access $display_name website and services"
        
        # Extract CIDR blocks to a txt file
        cidr_file="$OUTPUT_DIR/$category/$service_name.txt"
        extract_cidrs "$service_path" "$cidr_file"
        
        # Read CIDRs from the file into an array
        cidrs=()
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                cidrs+=("$line")
            fi
        done < "$cidr_file"
        
        # Skip services with no CIDRs
        if [ ${#cidrs[@]} -eq 0 ]; then
            continue
        fi
        
        # Add service to JSON structure
        if command -v jq &> /dev/null; then
            # Convert cidrs array to JSON
            cidr_json=$(printf '%s\n' "${cidrs[@]}" | jq -R . | jq -s .)
            
            # Update the JSON file with service information
            jq --arg category "$category" \
               --arg service "$display_name" \
               --arg url "$service_url" \
               --arg desc "$description" \
               --argjson cidrs "$cidr_json" \
               '.categories[$category].services[$service] = {"url": $url, "description": $desc, "cidrs": $cidrs}' \
               "$OUTPUT_DIR/data.json.tmp" > "$OUTPUT_DIR/data.json.tmp2"
            
            mv "$OUTPUT_DIR/data.json.tmp2" "$OUTPUT_DIR/data.json.tmp"
        else
            # Fallback without jq - less reliable
            cidr_json=$(printf '%s' "\"$(printf '%s", "' "${cidrs[@]}" | sed 's/, "$//')\"")
            service_json="{\"url\": \"$service_url\", \"description\": \"$description\", \"cidrs\": [$cidr_json]}"
            sed -i "s/\"services\": {}/\"services\": {\"$display_name\": $service_json}/g" "$OUTPUT_DIR/data.json.tmp"
            sed -i "s/\"services\": {\"$display_name\"/\"services\": {\"$display_name\"/g" "$OUTPUT_DIR/data.json.tmp"
        fi
    done
done

# Fix trailing commas in JSON
sed -i 's/,}/}/g' "$OUTPUT_DIR/data.json.tmp"
sed -i 's/,\n}/\n}/g' "$OUTPUT_DIR/data.json.tmp"

# Move temporary file to final location
mv "$OUTPUT_DIR/data.json.tmp" "$OUTPUT_DIR/data.json"

echo "Data extraction complete. Files saved to $OUTPUT_DIR/data.json"