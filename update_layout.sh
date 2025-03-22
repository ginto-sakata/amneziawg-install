#!/bin/bash

# update_layout.sh - Updates the website layout with necessary features

# Set variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INDEX_FILE="$SCRIPT_DIR/static_website/index.html"

# Check if index.html exists
if [ ! -f "$INDEX_FILE" ]; then
    echo "Error: index.html not found at $INDEX_FILE"
    exit 1
fi

# The CTRL+hover feature is now built into index.html
# This script is kept for compatibility and future layout updates
echo "Layout update complete. CTRL+hover feature is already built into index.html" 