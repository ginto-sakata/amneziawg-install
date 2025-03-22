#!/bin/bash
# test_website.sh - Complete testing script with proper name formatting

# Set variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Try to get domain name, fallback to IP if not available
SERVER_DOMAIN=$(hostname -f 2>/dev/null || hostname)
if [ -z "$SERVER_DOMAIN" ] || [ "$SERVER_DOMAIN" = "localhost" ]; then
    SERVER_DOMAIN=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1 | head -1)
fi
WEB_PORT=8080

echo "Working directory: $SCRIPT_DIR"

# 1. Clone/update iplist repository
echo "Cloning or updating iplist repository..."
if [ -d "$SCRIPT_DIR/iplist" ]; then
    (cd "$SCRIPT_DIR/iplist" && git pull)
else
    git clone -n --depth=1 --filter=tree:0 https://github.com/rekryt/iplist
    cd iplist
    git sparse-checkout set --no-cone /config
    git checkout
    cd "$SCRIPT_DIR"
fi

# 2. Generate data
echo "Generating data from iplist repository..."
chmod +x generate_data.sh
./generate_data.sh ./iplist/config ./static_website/data.json ./descriptions.json

# 3. Transform data for better organization
echo "Transforming data for website display..."
chmod +x transform_data.sh
./transform_data.sh

# 4. Update index.html with full-width layout
echo "Updating website layout with CTRL+hover feature..."
chmod +x update_layout.sh
./update_layout.sh

# 5. Serve website for testing
echo "Starting web server at http://${SERVER_DOMAIN}:${WEB_PORT}"
echo "Please open this URL in your browser."
echo "After selecting services, click 'Generate IP List' and copy the result."
echo "Press Ctrl+C when done to stop the server."

cd static_website
if command -v python3 &>/dev/null; then
    python3 -m http.server $WEB_PORT
elif command -v python &>/dev/null; then
    python -m SimpleHTTPServer $WEB_PORT
elif command -v php &>/dev/null; then
    php -S "0.0.0.0:$WEB_PORT"
elif command -v npx &>/dev/null; then
    npx http-server -p $WEB_PORT
else
    echo "No suitable web server found. Please install Python, PHP, or Node.js."
    exit 1
fi