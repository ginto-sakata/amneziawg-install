#!/bin/bash

# Set working directory to script location
cd "$(dirname "$0")"

# Function to download and process a list
download_list() {
    local url=$1
    local output_file=$2
    echo "Downloading $url to $output_file..."
    curl -s "$url" > "$output_file"
}

# Create lists directory if it doesn't exist
mkdir -p lists

# Download blocked lists
echo "Downloading blocked lists..."

# Russia blocked list
download_list "https://antifilter.network/download/ipsum.lst" "lists/ru_blocked.txt"
download_list "https://antifilter.network/download/subnet.lst" "lists/ru_blocked_2.txt"
cat lists/ru_blocked.txt lists/ru_blocked_2.txt | sort | uniq > lists/ru_blocked.txt
rm lists/ru_blocked_2.txt

# Ukraine blocked list
download_list "https://antifilter.network/download/uablacklist.lst" "lists/ua_blocked.txt"

# Download IP lists
echo "Downloading IP lists..."
./iplist_clone.sh

# Update timestamps
echo "Last updated: $(date)" > lists/last_update.txt

echo "Update complete!" 