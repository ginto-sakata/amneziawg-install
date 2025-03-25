#!/bin/bash

# Clone or update iplist repository

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
    git clone -n --depth=1 --filter=tree:0 https://github.com/rekryt/iplist
    cd iplist
    git sparse-checkout set --no-cone /config
    git checkout
    cd "$WORKING_DIR"
fi

echo "iplist repository is ready at $IPLIST_DIR"