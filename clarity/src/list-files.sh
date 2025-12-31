find . -type f -exec sh -c '
    echo "=== File: $1 ===" >> file_contents_log.txt
    echo "\`\`\`" >> file_contents_log.txt
    if [ -f "$1" ] && [ -r "$1" ]; then
        cat "$1" >> file_contents_log.txt
    else
        echo "[Cannot read file]" >> file_contents_log.txt
    fi
    echo "\`\`\`" >> file_contents_log.txt
    echo "" >> file_contents_log.txt
' _ {} \;
