#!/bin/bash

DB_DIR="/home/$(whoami)/autopatch/AutoPatch/codeql_db"
ROOT_DIR="/home/$(whoami)/autopatch/AutoPatch/CVE-list"
PYTHON_SCRIPT="/home/$(whoami)/autopatch/AutoPatch/src/eval/code_fixer.py" 
use_parallel=true


job_count=0
MAX_JOBS=16  # adjust based on your CPU/memory capacity
# Function to manage background jobs
wait_for_jobs() {
    while (( $(jobs -r | wc -l) >= MAX_JOBS )); do
        sleep 1
    done
}

find "$ROOT_DIR" -type f -path "*/original_code.txt" | while read -r code_txt; do

    # Directory where JSON file lives
    code_dir=$(dirname "$code_txt")
    # Get base name without extension (e.g., "augmented")
    base_name=$(basename "$code_txt" .txt)
    # Go two levels up to get CVE base dir: .../CVE-XXX-XXX/
    CVE_DIR=$(dirname "$code_txt")
    CVE_NAME=$(basename "$CVE_DIR")
    INFO_JSON="$CVE_DIR/info.json"

    # Construct DB path (e.g., .../augmented_db)
    db_path="$DB_DIR/$CVE_NAME/${base_name}_db"

    mkdir -p "$DB_DIR/$CVE_NAME"
    # Skip if DB already exists
    if [[ -d "$db_path" ]]; then
        echo "[SKIP] DB exists: $db_path"
        continue
    fi

    # Check if the directory ends with "EMPTY_CVE" or "BACKUP"
    if [[ "$CVE_DIR" == *"EMPTY_CVE"* || "$CVE_DIR" == *"BACKUP"* ]]; then
        echo "[SKIP] Skipping EMPTY_CVE or BACKUP directory: $CVE_DIR"
        continue
    fi

    if [[ ! -f "$INFO_JSON" ]]; then
        echo "[SKIP] info.json not found for: $code_txt"
        continue
    fi

    # Extract programming language from info.json using jq
    language=$(jq -r '.programming_language' "$INFO_JSON")
    if [[ "$language" == "null" || -z "$language" ]]; then
        echo "[SKIP] No programming_language in $INFO_JSON"
        continue
    fi

    echo "[INFO] Processing: $code_txt"
    echo "[INFO] Language: $language"

    if $use_parallel; then
        wait_for_jobs
        (
            dir=$(mktemp -d)
            cd "$dir" || exit 1
            python3 "$PYTHON_SCRIPT" --code_path "$code_txt" --db_path "$db_path" --language "$language"
            rm -rf "$dir"
        ) &
    else
        python3 "$PYTHON_SCRIPT" --code_path "$code_txt" --db_path "$db_path" --language "$language"
        if [ $? -eq 255 ]; then
            echo "Python script exited with -1, stopping the process."
            break
        fi
    fi
    echo
done



find "$ROOT_DIR" -type f -path "*/out_v2/code/*.json" | \
grep -E '.*/out_v2/code/[^/]+\.json$' | while read -r code_json; do

    # Directory where JSON file lives
    code_dir=$(dirname "$code_json")
    # Get base name without extension (e.g., "augmented")
    base_name=$(basename "$code_json" .json)
    # Go two levels up to get CVE base dir: .../CVE-XXX-XXX/
    CVE_DIR=$(dirname "$code_json" | awk -F'/out_v2' '{print $1}')
    CVE_NAME=$(basename "$CVE_DIR")
    INFO_JSON="$CVE_DIR/info.json"

    # Construct DB path (e.g., .../augmented_db)
    db_path="$DB_DIR/$CVE_NAME/${base_name}_db"

    # Skip if DB already exists
    if [[ -d "$db_path" ]]; then
        echo "[SKIP] DB exists: $db_path"
        continue
    fi

    if [[ ! -f "$INFO_JSON" ]]; then
        echo "[SKIP] info.json not found for: $code_json"
        continue
    fi

    # Extract programming language from info.json using jq
    language=$(jq -r '.programming_language' "$INFO_JSON")
    if [[ "$language" == "null" || -z "$language" ]]; then
        echo "[SKIP] No programming_language in $INFO_JSON"
        continue
    fi

    echo "[INFO] Processing: $code_json"
    echo "[INFO] Language: $language"

    if $use_parallel; then
        wait_for_jobs
        (
            dir=$(mktemp -d)
            cd "$dir" || exit 1
            python3 "$PYTHON_SCRIPT" --code_path "$code_json" --db_path "$db_path" --language "$language"
            rm -rf "$dir"
        ) &
    else
        python3 "$PYTHON_SCRIPT" --code_path "$code_json" --db_path "$db_path" --language "$language"
        if [ $? -eq 255 ]; then
            echo "Python script exited with -1, stopping the process."
            break
        fi
    fi
    echo
done