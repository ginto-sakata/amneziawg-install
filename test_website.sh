#!/bin/bash
# test_website.sh - Complete testing script with proper name formatting

# Check if required commands are available
for cmd in jq python3; do
    if ! command -v $cmd &> /dev/null; then
        echo "Error: $cmd is not installed"
        exit 1
    fi
done

# Create output directory
mkdir -p static_website

# Check if required files exist
for file in services.json categories.json descriptions.json; do
    if [ ! -f "$file" ]; then
        echo "Error: $file not found"
        exit 1
    fi
done

# Check if iplist directory exists
if [ ! -d "iplist" ]; then
    echo "Error: iplist directory not found"
    exit 1
fi

# Generate CIDR data and copy required files
echo "Generating CIDR data..."
./generate_data.sh

# Start Python HTTP server
echo "Starting HTTP server..."
cd static_website
python3 -m http.server 8080