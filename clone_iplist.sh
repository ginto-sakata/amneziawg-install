#!/bin/bash

# Clone or update iplist repository
# This script follows the same pattern used in amneziawg-install.sh

WORKING_DIR=$(pwd)
IPLIST_DIR="$WORKING_DIR/iplist"

# Check if iplist directory already exists
if [ -d "$IPLIST_DIR" ]; then
    echo "Updating existing iplist repository..."
    cd "$IPLIST_DIR"
    git pull
    cd "$WORKING_DIR"
else
    echo "Cloning iplist repository..."
    git clone --depth=1 https://github.com/rekryt/iplist
    cd iplist
    git sparse-checkout init
    git sparse-checkout set config/
    cd "$WORKING_DIR"
fi

echo "iplist repository is ready at $IPLIST_DIR"