#!/bin/bash

# Path to the iplist repository
IPLIST_DIR="$1"
OUTPUT_FILE="$2"

# Initialize the JSON structure
echo "{" > "$OUTPUT_FILE"

# Process each category directory
category_count=0
categories=$(find "$IPLIST_DIR/config" -mindepth 1 -maxdepth 1 -type d | sort)

for category_path in $categories; do
    category=$(basename "$category_path")
    
    # Skip hidden directories
    if [[ "$category" == .* ]]; then
        continue
    fi
    
    # Add comma if not the first category
    if [ $category_count -gt 0 ]; then
        echo "," >> "$OUTPUT_FILE"
    fi
    
    # Format category name (capitalize, replace underscores)
    category_display=$(echo "$category" | sed -e 's/_/ /g' -e 's/\b\(.\)/\u\1/g')
    
    echo "  \"$category_display\": {" >> "$OUTPUT_FILE"
    echo "    \"services\": {" >> "$OUTPUT_FILE"
    
    # Process each service in the category
    service_count=0
    services=$(find "$category_path" -name "*.json" | sort)
    
    for service_path in $services; do
        service_file=$(basename "$service_path")
        service_name="${service_file%.json}"
        
        # Skip if service name starts with a dot
        if [[ "$service_name" == .* ]]; then
            continue
        fi
        
        # Add comma if not the first service
        if [ $service_count -gt 0 ]; then
            echo "," >> "$OUTPUT_FILE"
        fi
        
        # Format service name (capitalize, replace underscores)
        service_display=$(echo "$service_name" | sed -e 's/_/ /g' -e 's/\b\(.\)/\u\1/g')
        
        # Keep domain extension for display purposes
        domain=""
        url=""
        
        # Check if it's a known domain
        if [[ "$service_name" == *".com" ]] || [[ "$service_name" == *".org" ]] || 
           [[ "$service_name" == *".net" ]] || [[ "$service_name" == *".io" ]] || 
           [[ "$service_name" == *".app" ]]; then
            # Use service name as URL
            url="https://www.$service_name"
            domain="$service_name"
        else
            # Try to guess URL
            domain=$(echo "$service_display" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/g')
            url="https://$domain.com"
        fi
        
        # Create a simple description
        description="Access $service_display website and services"
        
        # Extract CIDR blocks
        cidrs=$(grep -o '"cidr4": \[[^]]*\]' "$service_path" | sed 's/"cidr4": \[\(.*\)\]/\1/' | tr -d ' "')
        
        echo "      \"$service_display\": {" >> "$OUTPUT_FILE"
        echo "        \"icon\": \"icons/$category/$service_name.png\"," >> "$OUTPUT_FILE"
        echo "        \"url\": \"$url\"," >> "$OUTPUT_FILE"
        echo "        \"description\": \"$description\"," >> "$OUTPUT_FILE"
        echo "        \"cidrs\": [$cidrs]" >> "$OUTPUT_FILE"
        echo -n "      }" >> "$OUTPUT_FILE"
        
        service_count=$((service_count + 1))
    done
    
    echo "" >> "$OUTPUT_FILE"
    echo "    }" >> "$OUTPUT_FILE"
    echo -n "  }" >> "$OUTPUT_FILE"
    
    category_count=$((category_count + 1))
done

echo "" >> "$OUTPUT_FILE"
echo "}" >> "$OUTPUT_FILE" 