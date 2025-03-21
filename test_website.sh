#!/bin/bash

set -e

WORKING_DIR=~/amneziawg-install
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | head -1)
WEB_PORT=8080
REPO_URL="https://github.com/ginto-sakata/amneziawg-install.git"

# Check if we're already in the right repository directory
if [ "$SCRIPT_DIR" != "$WORKING_DIR" ]; then
    # Create working directory if it doesn't exist
    mkdir -p "$WORKING_DIR"
    
    # Clone or update the amneziawg-install repository directly to ~/amneziawg
    if [ -d "$WORKING_DIR/.git" ]; then
        echo "Updating amneziawg-install repository in $WORKING_DIR..."
        cd "$WORKING_DIR"
        git pull
    else
        echo "Cloning amneziawg-install repository to $WORKING_DIR..."
        # Clone to a temp directory first
        TEMP_CLONE_DIR=$(mktemp -d)
        git clone "$REPO_URL" "$TEMP_CLONE_DIR"
        
        # Move all contents to WORKING_DIR
        cp -r "$TEMP_CLONE_DIR/"* "$TEMP_CLONE_DIR/".* "$WORKING_DIR/" 2>/dev/null || true
        rm -rf "$TEMP_CLONE_DIR"
        
        cd "$WORKING_DIR"
    fi
else
    # We're already in the repository
    echo "Already in amneziawg-install repository directory: $WORKING_DIR"
    cd "$WORKING_DIR"
fi

echo "Working in directory: $WORKING_DIR"

# 1. Download or clone iplist/config
if [ -d "iplist" ]; then
    echo "Updating iplist repository..."
    cd iplist
    git pull
    cd ..
else
    echo "Cloning iplist repository..."
    git clone -n --depth=1 --filter=tree:0 https://github.com/rekryt/iplist
    cd iplist
    git sparse-checkout set --no-cone /config
    git checkout
    cd ..
fi

# 2. Generate data
cp -r ./iplist/config/ ./static_website/config/ 2>/dev/null || true
chmod +x generate_data.sh
./generate_data.sh ./static_website ./static_website/data.json


# 3. Serve website for testing
echo -e "${GREEN}Starting web server using Python 3 at http://${SERVER_IP}:${WEB_PORT}${NC}"
echo -e "${GREEN}Please open this URL in your browser.${NC}"
echo -e "${GREEN}After selecting services, click 'Generate IP List' and copy the result.${NC}"
echo -e "${ORANGE}Press Ctrl+C when done to continue with the installation.${NC}"

cd cd static_website
# Use Python's HTTP server if available
if command -v python3 &>/dev/null; then
    python3 -m http.server $WEB_PORT
elif command -v python &>/dev/null; then
    python -m SimpleHTTPServer $WEB_PORT
# Use PHP's built-in server if available
elif command -v php &>/dev/null; then
    php -S "localhost:$WEB_PORT"
# Use Node.js http-server if available
elif command -v npx &>/dev/null; then
    npx http-server -p $WEB_PORT
else
    echo "Error: No suitable web server found."
    echo "Please install Python, PHP, or Node.js to serve the website."
    echo "Alternatively, open website/index.html directly in your browser."
    exit 1
fi