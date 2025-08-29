#!/bin/bash

# Define the destination folder
DEST="out"

# Create destination if it doesn't exist
mkdir -p "$DEST"

# Loop through all out_dir folders and move their contents
find . -type d -name "out_dir" | while read -r dir; do
    echo "Moving contents from $dir"
    mv "$dir"/* "$DEST"/ 2>/dev/null
done

echo "All files moved into $DEST/"
