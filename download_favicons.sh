#!/bin/bash

# Script to download favicons from iplist repository config
# Usage: ./download_favicons.sh <output_icons_dir>

# Parameters
DEFAULT_ICONS_DIR="./static_website/icons"
ICONS_DIR="${1:-$DEFAULT_ICONS_DIR}"
IPLIST_CONFIG="./static_website/config"

# Check if output directory is provided
if [ -z "$1" ]; then
    echo "Using default output directory: $DEFAULT_ICONS_DIR"
    ICONS_DIR="$DEFAULT_ICONS_DIR"
fi

echo "Icons will be saved to: $(realpath "$ICONS_DIR")"

# Install dependencies if not available
if ! command -v curl &> /dev/null; then
    echo "curl is required. Installing..."
    apt-get update && apt-get install -y curl
fi

# Create output directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ABSOLUTE_ICONS_DIR="$(realpath "${SCRIPT_DIR}/${ICONS_DIR}")"
mkdir -p "$ABSOLUTE_ICONS_DIR"

# Check if jq is available for better JSON parsing
if ! command -v jq &> /dev/null; then
    echo "jq is not installed. Will use basic grep for JSON parsing."
    USE_JQ=0
else
    USE_JQ=1
fi

extract_domain() {
    local json_file="$1"
    
    if [ "$USE_JQ" -eq 1 ]; then
        jq -r '.domains[0]' "$json_file" 2>/dev/null
    else
        grep -o '"domains": \[[^]]*\]' "$json_file" | 
            sed 's/"domains": \[\([^,]*\).*/\1/' | 
            tr -d ' "'
    fi
}

download_favicon() {
    local domain="$1"
    local category="$2"
    local output_dir="$3"
    local service_name="$4"
    
    echo "Downloading favicon for $domain (Category: $category)..."
    
    # Create category directory if it doesn't exist
    mkdir -p "$output_dir/$category"
    
    # Try different favicon paths
    local favicon_urls=(
        "https://${domain}/favicon.ico"
        "https://www.${domain}/favicon.ico"
        "https://${domain}/favicon.png"
        "https://www.${domain}/favicon.png"
        "https://${domain}/assets/favicon.ico"
        "https://www.${domain}/assets/favicon.ico"
        "https://${domain}/apple-touch-icon.png"
        "https://www.${domain}/apple-touch-icon.png"
    )
    
    for url in "${favicon_urls[@]}"; do
        echo "Trying $url"
        
        # Create a filename based on the service name
        local filename="${output_dir}/${category}/${service_name}.png"
        
        # Download the favicon with curl
        if curl -s -o "$filename" -L "$url" && [ -s "$filename" ]; then
            echo "✓ Downloaded favicon for $domain from $url"
            return 0
        fi
    done
    
    # Try Google's favicon service as fallback
    local google_favicon_url="https://www.google.com/s2/favicons?domain=${domain}&sz=64"
    local filename="${output_dir}/${category}/${service_name}.png"
    
    echo "Trying Google favicon service: $google_favicon_url"
    if curl -s -o "$filename" -L "$google_favicon_url" && [ -s "$filename" ]; then
        echo "✓ Downloaded favicon for $domain from Google favicon service"
        return 0
    fi
    
    # If we reach here, we failed to download a favicon
    echo "✗ Failed to download favicon for $domain"
    
    # Create a fallback colored box with first letter
    local first_letter=$(echo "$domain" | head -c 1 | tr '[:lower:]' '[:upper:]')
    
    # Use a default placeholder image
    echo "Using placeholder image for $domain"
    echo "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABhWlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw0AYht+mSkUqDnYQcchQnSyIijhqFYpQIdQKrTqYXPojNGlIUlwcBdeCgz+LVQcXZ10dXAVB8AfE0clJ0UVK/C4ptIjxjuMe3vvel7vvAKFRYarZNQGommWk4jExm1sTvV/oRRBhDGISM/VEejEDz/F1Dx/f76I8y7vuz9Gv5E0G+ETiOaYbFvEG8fSmpXPeJw6zkqQQnxOPGnRB4keuyy6/cS447PfMkZFMz4lDxGKpg+UOZiVDJZ4ijiiqRvlC1mWF8xZntVJjrXvyFwbz2soy12kOIY5FLEGCCAVVlFCGhRitGikmUrQf9/APO36JXDK5SmDkWEAFKiTHD/4Hv3trFqYm3aRQDOh+se2PMSC4CzRrtv19bNuNEyDwDFxpLX+lDsx8kl5raZEjoG8buLhuafIecLkDDD3pkiE5kp+WUCgA72f0TTlg4BboW3P71j7H6QOQoV4t3wAHh8BIkbLXPN7d1d7bv2ca/f0A+ldy00vHW2IAAAAGYktHRAD/AP8A/6C9p5MAAAAJcEhZcwAALiMAAC4jAXilP3YAAAAHdElNRQfnAwMRLSNKiVyIAAAAGXRFWHRDb21tZW50AENyZWF0ZWQgd2l0aCBHSU1QV4EOFwAAAGdJREFUOMtjZGBgYPj//z8DFtC2j51BgIeFQYCZkeHAZXcwn4EBGaAbjPz/HymAAXYNjAwMDCLHbRgY/v9H00D7nx3ZYAYDA/pjhM9sBkYGBgbj24cgjEcpw2MG2y8hhlAXDAwfzJD5AJE7F4dO7qKFAAAAAElFTkSuQmCC" | base64 -d > "$filename"
    
    return 1
}

echo "Starting favicon download from iplist config at $IPLIST_CONFIG"
echo "Favicons will be saved to $ABSOLUTE_ICONS_DIR"
echo "---------------------------------------------"

# Process each category folder in the iplist config
for category_path in "$IPLIST_CONFIG"/*; do
    # Skip if not a directory
    if [ ! -d "$category_path" ]; then
        continue
    fi
    
    # Get category name from directory name
    category=$(basename "$category_path")
    
    # Skip hidden directories
    if [[ "$category" == .* ]]; then
        continue
    fi
    
    echo "Processing category: $category"
    mkdir -p "$ABSOLUTE_ICONS_DIR/$category"
    
    # Process each JSON file in the category
    for json_file in "$category_path"/*.json; do
        # Skip if not a file or if no files match the pattern
        if [ ! -f "$json_file" ] || [ "$json_file" = "$category_path/*.json" ]; then
            continue
        fi
        
        # Get service name from filename
        service_name=$(basename "$json_file" .json)
        
        # Skip if hidden file
        if [[ "$service_name" == .* ]]; then
            continue
        fi
        
        # Extract domain from JSON file
        domain=$(extract_domain "$json_file")
        
        # If extraction failed, use service name as domain
        if [ -z "$domain" ] || [ "$domain" == "null" ]; then
            domain="$service_name"
        fi
        
        # Create a more readable service name for display
        display_name=$(echo "$service_name" | sed -E 's/\./-/g' | sed -E 's/(^|-)([a-z])/\U\2/g')
        
        # Download favicon for this domain
        download_favicon "$domain" "$category" "$ABSOLUTE_ICONS_DIR" "$service_name"
    done
done

echo "---------------------------------------------"
echo "Favicon download complete. Results saved to $ABSOLUTE_ICONS_DIR"

# Update index.html to use local favicons
echo "Updating index.html to use local favicons..."
sed -i 's|https://www.google.com/s2/favicons?domain=${urlObj.hostname}&sz=64|icons/${category}/${serviceName.toLowerCase().replace(/ /g, ".")}.png|g' static_website/index.html

# Create a .gitkeep file in each category directory
# This ensures that empty directories are still tracked by git
find "$ABSOLUTE_ICONS_DIR" -type d -empty -exec touch {}/.gitkeep \; 