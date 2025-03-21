#!/bin/bash

set -e

WORKING_DIR=~/amneziawg
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_PORT=8000

# Create working directory if it doesn't exist
mkdir -p "$WORKING_DIR"
cd "$WORKING_DIR"

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

# 2. Copy static website files
mkdir -p website
if [ -d "$SCRIPT_DIR/static_website" ]; then
    echo "Copying static website files..."
    cp -r "$SCRIPT_DIR/static_website/"* website/
else
    echo "Error: Static website files not found!"
    exit 1
fi

# Make generate_data.sh executable
chmod +x website/generate_data.sh 2>/dev/null || true

# 3. Handle icons
mkdir -p website/icons
if [ -d "$SCRIPT_DIR/icons" ]; then
    echo "Copying pre-downloaded icons..."
    cp -r "$SCRIPT_DIR/icons/"* website/icons/
else
    echo "No pre-downloaded icons found. Running icon downloader..."
    mkdir -p icons
    bash "$SCRIPT_DIR/download_favicons.sh" icons
    cp -r icons/* website/icons/
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