#!/bin/bash

# Standalone script to download favicons from iplist repository config
# This script automatically clones the iplist repository and downloads favicons
# Usage: ./download_favicons.sh <output_icons_dir>

# Parameters
DEFAULT_ICONS_DIR="./icons"
ICONS_DIR="${1:-$DEFAULT_ICONS_DIR}"
AMNEZIAWG_DIR=~/amneziawg
IPLIST_DIR="${AMNEZIAWG_DIR}/iplist"
IPLIST_CONFIG="${IPLIST_DIR}/config"

# Check if output directory is provided
if [ -z "$ICONS_DIR" ]; then
    echo "Using default output directory: $DEFAULT_ICONS_DIR"
    ICONS_DIR="$DEFAULT_ICONS_DIR"
fi

echo "Icons will be saved to: $(realpath "$ICONS_DIR")"

# Create amneziawg directory if it doesn't exist
mkdir -p "$AMNEZIAWG_DIR"

# Install dependencies if not available
if ! command -v curl &> /dev/null; then
    echo "curl is required. Installing..."
    apt-get update && apt-get install -y curl
fi

if ! command -v git &> /dev/null; then
    echo "git is required. Installing..."
    apt-get update && apt-get install -y git
fi

# Clone or update iplist repository
if [ -d "$IPLIST_DIR" ]; then
    echo "Updating existing iplist repository..."
    cd "$IPLIST_DIR"
    git pull origin master
else
    echo "Cloning iplist repository..."
    git clone -n --depth=1 --filter=tree:0 https://github.com/rekryt/iplist "$IPLIST_DIR"
    cd "$IPLIST_DIR"
    git sparse-checkout set --no-cone "config"
    git checkout
fi

# Check if iplist config directory exists after cloning
if [ ! -d "$IPLIST_CONFIG" ]; then
    echo "Error: iplist config directory not found after cloning."
    exit 1
fi

# Create output directory (using absolute path based on script location)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ABSOLUTE_ICONS_DIR="$(realpath "${SCRIPT_DIR}/${ICONS_DIR}")"
mkdir -p "$ABSOLUTE_ICONS_DIR"

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
    
    # If we reach here, we failed to download a favicon
    echo "✗ Failed to download favicon for $domain"
    
    # Create a fallback colored box with first letter
    local first_letter=$(echo "$domain" | head -c 1 | tr '[:lower:]' '[:upper:]')
    local hash=$(echo -n "$domain" | md5sum | head -c 6)
    
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
    
    # Process each JSON file in the category
    for json_file in "$category_path"/*.json; do
        # Skip if not a file or if no files match the pattern
        if [ ! -f "$json_file" ] || [ "$json_file" = "$category_path/*.json" ]; then
            continue
        fi
        
        # Get domain name from filename
        domain=$(basename "$json_file" .json)
        
        # Skip if hidden file
        if [[ "$domain" == .* ]]; then
            continue
        fi
        
        # Extract service name (same as domain in this case)
        service_name="$domain"
        
        # Download favicon for this domain
        download_favicon "$domain" "$category" "$ABSOLUTE_ICONS_DIR" "$service_name"
    done
done

echo "---------------------------------------------"
echo "Favicon download complete. Results saved to $ABSOLUTE_ICONS_DIR"
echo "Add these favicons to git with: git add $ICONS_DIR"

# Create a .gitkeep file in each category directory
# This ensures that empty directories are still tracked by git
find "$ABSOLUTE_ICONS_DIR" -type d -empty -exec touch {}/.gitkeep \; 