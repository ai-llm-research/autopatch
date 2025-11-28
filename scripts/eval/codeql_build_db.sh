#!/bin/bash

CODE_QL_DIR="/home/$(whoami)/autopatch/codeql"
DB_DIR="/home/$(whoami)/autopatch/AutoPatch/codeql_db"
ROOT_DIR="/home/$(whoami)/autopatch/AutoPatch/CVE-list"
PYTHON_SCRIPT="/home/$(whoami)/autopatch/AutoPatch/src/autopatch/code_fixer.py" 
use_parallel=true

find "$ROOT_DIR" -type f -path "*_fixed*" | while read -r code_path; do

    # Directory where JSON file lives
    code_dir=$(dirname "$code_path")
    # Get base name without extension (e.g., "augmented") .cpp or .c
    base_name=$(basename "$code_path" _fixed.cpp)
    base_name=$(basename "$base_name" _fixed.c)

    # Go two levels up to get CVE base dir: .../CVE-XXX-XXX/
    if [[ "$code_path" == *"out_v2/code/"* ]]; then
        CVE_DIR=$(dirname "$(dirname "$(dirname "$code_path")")")
    else
        CVE_DIR=$(dirname "$code_path")
    fi

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
        echo "[SKIP] info.json not found for: $code_path"
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

    if [[ "$language" == "c" ]];  then
        compiler_option="/usr/bin/gcc"
    elif [[ "$language" == "cpp" ]]; then
        compiler_option="/usr/bin/g++"
    else
        echo "[SKIP] Unsupported programming language: $language"
        continue
    fi

    if ! "${CODE_QL_DIR}/codeql" database create "${db_path}" --language=c-cpp --command="${compiler_option} -c ${code_path}" --overwrite; then
        echo "CodeQL database creation failed. Removing ${db_path}"
        rm -rf "${db_path}"
    fi
    echo
done

