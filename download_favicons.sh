#!/bin/bash

# Script to download favicons from websites in the iplist repository
# Usage: ./download_favicons.sh <path_to_iplist_dir> <output_icons_dir>

# Parameters
IPLIST_DIR="$1"
ICONS_DIR="$2"

if [ -z "$IPLIST_DIR" ] || [ -z "$ICONS_DIR" ]; then
    echo "Usage: $0 <path_to_iplist_dir> <output_icons_dir>"
    exit 1
fi

# Create output directory
mkdir -p "$ICONS_DIR"

# Install dependencies if not available
if ! command -v curl &> /dev/null; then
    echo "curl is required. Installing..."
    apt-get update && apt-get install -y curl
fi

download_favicon() {
    local service="$1"
    local output_dir="$2"
    local attempt=1
    local url
    
    echo "Downloading favicon for $service..."
    
    # Try several common favicon locations with domain variations
    # First, clean up the service name to get a domain
    local domain=$(echo "$service" | tr '[:upper:]' '[:lower:]' | sed 's/ /-/g')
    
    # Try different domain suffixes if they're not in the service name
    local domains=("$domain" "${domain}.com" "${domain}.org" "${domain}.net" "${domain}.io")
    
    for d in "${domains[@]}"; do
        # Skip if the domain already has a suffix
        if [[ "$service" == *".com"* ]] || [[ "$service" == *".org"* ]] || [[ "$service" == *".net"* ]] || [[ "$service" == *".io"* ]]; then
            domains=("$domain")
            break
        fi
    done
    
    for d in "${domains[@]}"; do
        # Try different favicon paths
        local favicon_urls=(
            "https://${d}/favicon.ico"
            "https://www.${d}/favicon.ico"
            "https://${d}/favicon.png"
            "https://www.${d}/favicon.png"
            "https://${d}/assets/favicon.ico"
            "https://www.${d}/assets/favicon.ico"
        )
        
        for url in "${favicon_urls[@]}"; do
            echo "Trying $url"
            
            # Create a filename based on the service
            local filename="${output_dir}/${service}.png"
            
            # Download the favicon with curl
            if curl -s -o "$filename" -L "$url" && [ -s "$filename" ]; then
                echo "Downloaded favicon for $service from $url"
                return 0
            fi
        done
    done
    
    # If we reach here, we failed to download a favicon
    echo "Failed to download favicon for $service"
    
    # Create a fallback colored box with first letter
    local first_letter=$(echo "$service" | head -c 1 | tr '[:lower:]' '[:upper:]')
    local hash=$(echo -n "$service" | md5sum | head -c 6)
    
    # Use a default placeholder image
    echo "Using placeholder image for $service"
    echo "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAABhWlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw0AYht+mSkUqDnYQcchQnSyIijhqFYpQIdQKrTqYXPojNGlIUlwcBdeCgz+LVQcXZ10dXAVB8AfE0clJ0UVK/C4ptIjxjuMe3vvel7vvAKFRYarZNQGommWk4jExm1sTvV/oRRBhDGISM/VEejEDz/F1Dx/f76I8y7vuz9Gv5E0G+ETiOaYbFvEG8fSmpXPeJw6zkqQQnxOPGnRB4keuyy6/cS447PfMkZFMz4lDxGKpg+UOZiVDJZ4ijiiqRvlC1mWF8xZntVJjrXvyFwbz2soy12kOIY5FLEGCCAVVlFCGhRitGikmUrQf9/APO36JXDK5SmDkWEAFKiTHD/4Hv3trFqYm3aRQDOh+se2PMSC4CzRrtv19bNuNEyDwDFxpLX+lDsx8kl5raZEjoG8buLhuafIecLkDDD3pkiE5kp+WUCgA72f0TTlg4BboW3P71j7H6QOQoV4t3wAHh8BIkbLXPN7d1d7bv2ca/f0A+ldy00vHW2IAAAAGYktHRAD/AP8A/6C9p5MAAAAJcEhZcwAALiMAAC4jAXilP3YAAAAHdElNRQfnAwMRLSNKiVyIAAAAGXRFWHRDb21tZW50AENyZWF0ZWQgd2l0aCBHSU1QV4EOFwAAAGdJREFUOMtjZGBgYPj//z8DFtC2j51BgIeFQYCZkeHAZXcwn4EBGaAbjPz/HymAAXYNjAwMDCLHbRgY/v9H00D7nx3ZYAYDA/pjhM9sBkYGBgbj24cgjEcpw2MG2y8hhlAXDAwfzJD5AJE7F4dO7qKFAAAAAElFTkSuQmCC" | base64 -d > "$filename"
    
    return 1
}

# Process each category
find "$IPLIST_DIR/config" -mindepth 1 -maxdepth 1 -type d -not -path "*/\.*" | while read -r category_path; do
    category=$(basename "$category_path")
    category_icons_dir="$ICONS_DIR/$category"
    mkdir -p "$category_icons_dir"
    
    # Process each service in the category
    find "$category_path" -name "*.json" | while read -r service_path; do
        service_file=$(basename "$service_path")
        service_name="${service_file%.json}"
        
        # Skip hidden files
        if [[ "$service_name" == .* ]]; then
            continue
        fi
        
        # Format service name (capitalize, replace underscores)
        service_display=$(echo "$service_name" | sed -e 's/_/ /g' -e 's/\b\(.\)/\u\1/g')
        
        download_favicon "$service_display" "$category_icons_dir"
    done
done

echo "Favicons downloaded to $ICONS_DIR" 