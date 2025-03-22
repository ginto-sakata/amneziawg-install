#!/bin/bash

# Directory containing the IP list configuration files
CONFIG_DIR="${1:-./iplist/config}"
OUTPUT_FILE="${2:-./static_website/data.json}"
DESCRIPTIONS_FILE="${3:-./descriptions.json}"

echo "Generating data from $CONFIG_DIR to $OUTPUT_FILE..."

# Ensure output directory exists
mkdir -p $(dirname "$OUTPUT_FILE")

# Create initial JSON structure
cat > "$OUTPUT_FILE" << EOF
{
  "categories": {
  }
}
EOF

# Check if jq is available
if command -v jq &> /dev/null; then
    echo "Using jq for JSON processing"
    HAS_JQ=1
else
    echo "Warning: jq not found, will use basic text processing (less reliable)"
    echo "Install jq for better results: apt-get install jq"
    HAS_JQ=0
fi

# Load descriptions
if [ -f "$DESCRIPTIONS_FILE" ]; then
    echo "Loading descriptions from $DESCRIPTIONS_FILE"
    DESCRIPTIONS=$(cat "$DESCRIPTIONS_FILE")
else
    echo "Warning: descriptions.json not found"
    DESCRIPTIONS="{}"
fi

# Process each category directory
find "$CONFIG_DIR" -mindepth 1 -maxdepth 1 -type d | while read -r category_path; do
    category=$(basename "$category_path")
    
    # Skip hidden directories
    if [[ "$category" == .* ]]; then
        continue
    fi
    
    echo "Processing category: $category"
    
    # Add category to JSON
    if [ "$HAS_JQ" -eq 1 ]; then
        # Add the category using jq
        jq --arg cat "$category" '.categories[$cat] = {"services": {}}' "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
        mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
    else
        # Add category using sed (less reliable)
        sed -i "s/\"categories\": {/\"categories\": {\"$category\": {\"services\": {}},/g" "$OUTPUT_FILE"
    fi
    
    # Process each service file
    find "$category_path" -name "*.json" | while read -r service_file; do
        service_name=$(basename "$service_file" .json)
        
        # Skip hidden files
        if [[ "$service_name" == .* ]]; then
            continue
        fi
        
        echo "  Processing service: $service_name"
        
        # Extract data from service file
        if [ "$HAS_JQ" -eq 1 ]; then
            # Extract using jq
            url=$(jq -r '.url // ""' "$service_file")
            cidrs=$(jq -c '.cidr4 // []' "$service_file")
            
            # Extract domain from URL
            if [ -n "$url" ]; then
                domain=$(echo "$url" | sed -E 's#^https?://([^/]+).*#\1#')
            else
                # Fallback to first domain from domains array
                domain=$(jq -r '.domains[0] // ""' "$service_file")
            fi
            
            # Get description from descriptions.json
            description=$(echo "$DESCRIPTIONS" | jq -r --arg domain "$domain" '.[$domain] // "Access website and services"')
            
            # Skip if no domain or CIDR found
            if [ -z "$domain" ]; then
                echo "    No domain found, skipping"
                continue
            fi
            
            # Skip if no CIDRs (checking if cidrs is empty array or empty string)
            if [ "$cidrs" = "[]" ] || [ -z "$cidrs" ]; then
                echo "    No CIDRs found, skipping"
                continue
            fi
            
            # Add service to JSON
            jq --arg cat "$category" \
               --arg name "$service_name" \
               --arg url "$url" \
               --arg desc "$description" \
               --argjson cidrs "$cidrs" \
               '.categories[$cat].services[$name] = {"url": $url, "description": $desc, "cidrs": $cidrs}' \
               "$OUTPUT_FILE" > "$OUTPUT_FILE.tmp"
            mv "$OUTPUT_FILE.tmp" "$OUTPUT_FILE"
        else
            # Extract using grep/sed (less reliable)
            url=$(grep -o '"url":\s*"[^"]*"' "$service_file" | sed 's/"url":\s*"\([^"]*\)"/\1/')
            cidrs=$(grep -o '"cidr4":\s*\[[^]]*\]' "$service_file" | sed 's/"cidr4":\s*\[\(.*\)\]/\1/')
            
            # Extract domain from URL
            if [ -n "$url" ]; then
                domain=$(echo "$url" | sed -E 's#^https?://([^/]+).*#\1#')
            else
                # Fallback to first domain from domains array
                domain=$(grep -o '"domains":\s*\[[^]]*\]' "$service_file" | sed 's/"domains":\s*\[\s*"\([^"]*\).*/\1/')
            fi
            
            # Skip if no domain or CIDR found
            if [ -z "$domain" ]; then
                echo "    No domain found, skipping"
                continue
            fi
            
            # Skip if no CIDRs (checking if cidrs is empty array or empty string)
            if [ "$cidrs" = "[]" ] || [ -z "$cidrs" ]; then
                echo "    No CIDRs found, skipping"
                continue
            fi
            
            # Get description from descriptions.json
            description=$(echo "$DESCRIPTIONS" | grep -o "\"$domain\":\s*\"[^\"]*\"" | sed "s/\"$domain\":\s*\"\([^\"]*\)\"/\1/")
            if [ -z "$description" ]; then
                description="Access website and services"
            fi
            
            # Add service to JSON
            service_json="{\"url\":\"$url\",\"description\":\"$description\",\"cidrs\":$cidrs}"
            sed -i "s/\"services\": {}/\"services\": {\"$service_name\": $service_json}/g" "$OUTPUT_FILE"
        fi
    done
done

# Fix trailing commas (if any)
sed -i 's/,}/}/g' "$OUTPUT_FILE"
sed -i 's/},}/}}/g' "$OUTPUT_FILE"

# Fix the JSON if using sed method
if [ "$HAS_JQ" -eq 0 ]; then
    # Remove the trailing comma after the last category
    sed -i 's/,\s*}/}/g' "$OUTPUT_FILE"
fi

echo "Data generation complete. File saved to: $OUTPUT_FILE"