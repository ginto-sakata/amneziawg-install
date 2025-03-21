#!/bin/bash

set -e

WORKING_DIR=~/amneziawg
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_PORT=8000
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
    git clone https://github.com/iplist/iplist.git
fi

# 2. Create website directory and copy files
mkdir -p website
if [ -d "static_website" ]; then
    echo "Copying static website files..."
    cp -r static_website/* website/
else
    echo "Error: Static website files not found!"
    exit 1
fi

# Make generate_data.sh executable
chmod +x website/generate_data.sh 2>/dev/null || true

# 3. Handle icons
mkdir -p website/icons
if [ -d "icons" ]; then
    echo "Copying pre-downloaded icons..."
    cp -r icons/* website/icons/
else
    echo "No pre-downloaded icons found. Running icon downloader..."
    mkdir -p icons
    bash "$WORKING_DIR/download_favicons.sh" icons
    
    # Copy icons to website directory
    cp -r icons/* website/icons/
    
    echo ""
    echo "Icons have been downloaded and saved to $WORKING_DIR/icons"
    echo "To commit and push the icons to the repository:"
    echo "  cd $WORKING_DIR"
    echo "  git add icons"
    echo "  git commit -m 'Add downloaded icons'"
    echo "  git push origin master"
    echo ""
fi

# 4. Generate data.json
echo "Generating data.json..."
cd website
./generate_data.sh "../iplist" "data.json"
cd ..

# 5. Serve website for testing
echo "Starting web server on port $WEB_PORT..."
echo "Visit http://localhost:$WEB_PORT in your browser"
echo "Press Ctrl+C to stop the server"

# Use Python's HTTP server if available
if command -v python3 &>/dev/null; then
    cd website
    python3 -m http.server $WEB_PORT
elif command -v python &>/dev/null; then
    cd website
    python -m SimpleHTTPServer $WEB_PORT
# Use PHP's built-in server if available
elif command -v php &>/dev/null; then
    cd website
    php -S "localhost:$WEB_PORT"
# Use Node.js http-server if available
elif command -v npx &>/dev/null; then
    cd website
    npx http-server -p $WEB_PORT
else
    echo "Error: No suitable web server found."
    echo "Please install Python, PHP, or Node.js to serve the website."
    echo "Alternatively, open website/index.html directly in your browser."
    exit 1
fi 