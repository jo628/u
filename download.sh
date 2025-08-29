#!/bin/bash

# Get directory of this script
BASE_DIR="$(dirname "$(realpath "$0")")"

# Read links.txt line by line
i=1
while IFS= read -r url; do
    folder="$BASE_DIR/$i"
    if [ -d "$folder" ] && [ -n "$url" ]; then
        terminator --working-directory="$folder" -e "
            bash -c '
                echo \"Running main.py for $url\";
                python3 main.py -c ${url}learn/ -sc --browser chrome -q 720 --download-assets --download-captions;
                echo \"Finished for $url\";
                exec bash
            '
        " &
        sleep 1
    fi
    i=$((i+1))
done < "$BASE_DIR/links.txt"
