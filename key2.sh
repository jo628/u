#!/bin/bash

# Get directory of this script
BASE_DIR="$(dirname "$(realpath "$0")")"

# Read links.txt line by line
i=1
while IFS= read -r url; do
    folder="$BASE_DIR/$i"
    if [ -d "$folder" ]; then
        terminator --working-directory="$folder" -e "
            bash -c '
                echo \"Running key.py for $url\";
                python3 key2.py -c ${url}learn/ --browser chrome;
                echo \"Finished for $url\";
                exec bash
            '
        " &
        sleep 10
    fi
    i=$((i+1))
done < "$BASE_DIR/links.txt"
