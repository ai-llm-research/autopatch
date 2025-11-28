#!/bin/bash

CODE_QL_DIR="/home/$(whoami)/autopatch/codeql"
DB_DIR="/home/$(whoami)/autopatch/AutoPatch/codeql_db"
ROOT_DIR="/home/$(whoami)/autopatch/AutoPatch/CVE-list"
QUERY_DIR=/home/$(whoami)/autopatch/AutoPatch/ql-pack/queries
use_parallel=true

job_count=0
MAX_JOBS=16  # adjust based on your CPU/memory capacity
# Function to manage background jobs
wait_for_jobs() {
    while (( $(jobs -r | wc -l) >= MAX_JOBS )); do
        sleep 1
    done
}

# For Data-Flow Analysis
find "$ROOT_DIR" -type f -path "*_fixed*" | while read -r code_path; do

    # Directory where JSON file lives
    code_dir=$(dirname "$code_path")
    # Get base name without extension (e.g., "augmented") .cpp or .c
    base_name=$(basename "$code_path" _fixed.cpp)
    base_name=$(basename "$base_name" _fixed.c)

    # Go two levels up to get CVE base dir: .../CVE-XXX-XXX/
    if [[ "$code_path" == *"out_v2/code/"* ]]; then
        CVE_DIR=$(dirname "$(dirname "$(dirname "$code_path")")")
        OUTPUT_PATH="$CVE_DIR/out_v2/code/${base_name}_data_flow.csv"
        FUNCTION_LIST_PATH="$CVE_DIR/out_v2/code/${base_name}_all_functions.csv"
        VARIABLE_LIST_PATH="$CVE_DIR/out_v2/code/${base_name}_all_variables.csv"
        
    else
        CVE_DIR=$(dirname "$code_path")
        OUTPUT_PATH="$CVE_DIR/out_v2/${base_name}_data_flow.csv"
        FUNCTION_LIST_PATH="$CVE_DIR/out_v2/${base_name}_all_functions.csv"
        VARIABLE_LIST_PATH="$CVE_DIR/out_v2/${base_name}_all_variables.csv"
    fi

    CVE_NAME=$(basename "$CVE_DIR")
    INFO_JSON="$CVE_DIR/info.json"
    DB_PATH="$DB_DIR/$CVE_NAME/${base_name}_db"

    #####################################
    # Process data flow analysis
    #####################################
    echo "[INFO] Processing data flow analysis: $CVE_NAME => $OUTPUT_PATH"

    if [ ! -f "$FUNCTION_LIST_PATH" ]; then
        echo "[ERROR] $FUNCTION_LIST_PATH not exists, skipping."
        continue
    fi

    if [ ! -f "$VARIABLE_LIST_PATH" ]; then
        echo "[ERROR] $VARIABLE_LIST_PATH not exists, skipping."
        continue
    fi

    # Skip if output already exists
    if [ -f "$OUTPUT_PATH" ]; then
        echo "[SKIP] Output already exists at $OUTPUT_PATH, skipping."
        continue
    fi

    # Check if the directory ends with "EMPTY_CVE" or "BACKUP"
    if [[ "$CVE_DIR" == *"EMPTY_CVE"* || "$CVE_DIR" == *"BACKUP"* ]]; then
        echo "[SKIP] Skipping EMPTY_CVE or BACKUP directory: $CVE_DIR"
        continue
    fi

    # Get function and variable lists and merge them
    function_list="$(sed 's/^"\(.*\)"$/\1/' "$FUNCTION_LIST_PATH" | awk '{gsub(/"/, "\\\""); print "\"" $0 "\""}' | paste -sd, -)"
    variable_list="$(sed 's/^"\(.*\)"$/\1/' "$VARIABLE_LIST_PATH" | awk '{gsub(/"/, "\\\""); print "\"" $0 "\""}' | paste -sd, -)"

    # if [ -z "$function_list" ] && [ -z "$variable_list" ]; then
    #     echo $OUTPUT_PATH
    # fi

    [ -z "$function_list" ] && function_list='""'
    [ -z "$variable_list" ] && variable_list='""'

    # Construct merged list safely
    merged_list="["
    if [ -n "$function_list" ]; then
        merged_list+="$function_list"
    fi
    if [ -n "$function_list" ] && [ -n "$variable_list" ]; then
        merged_list+=","
    fi
    if [ -n "$variable_list" ]; then
        merged_list+="$variable_list"
    fi
    merged_list+="]"

    function_name=$(jq -r '.function_name' "$INFO_JSON")
    temp_bqrs_file=out_data_flow_"$base_name"_"$function_name".bqrs
    temp_csv_file=tmp_result_data_flow_"$base_name"_"$function_name".csv
    original_query_file="${QUERY_DIR}/data_flow_analysis.ql"
    temp_query_file="${QUERY_DIR}/data_flow_analysis_${base_name}_${function_name}.ql"
    
    cp "$original_query_file" "$temp_query_file"
    sed -i "s|<TARGET_FUNCTION_NAME>|$function_name|g; s|<VARIABLES_AND_FUNCTIONS_LIST>|$merged_list|g" "$temp_query_file" # [TODO]
    if $use_parallel; then
        wait_for_jobs
        (
            dir=$(mktemp -d)
            cd "$dir" || exit 1
            "${CODE_QL_DIR}/codeql" query run --database="$DB_PATH" "${temp_query_file}" --output="$temp_bqrs_file"
            "${CODE_QL_DIR}/codeql" bqrs decode --format=csv --output="${OUTPUT_PATH}" --no-titles "$temp_bqrs_file"
            awk '!seen[$0]++' "${OUTPUT_PATH}" > "$temp_csv_file" && mv "$temp_csv_file" "${OUTPUT_PATH}"
            rm -rf $temp_query_file
            rm -rf "$dir"
        ) &
    else
        "${CODE_QL_DIR}/codeql" query run --database="$DB_PATH" "${temp_query_file}" --output="$temp_bqrs_file"
        "${CODE_QL_DIR}/codeql" bqrs decode --format=csv --output="${OUTPUT_PATH}" --no-titles "$temp_bqrs_file"
        awk '!seen[$0]++' "${OUTPUT_PATH}" > "$temp_csv_file" && mv "$temp_csv_file" "${OUTPUT_PATH}"
        rm -rf $temp_query_file
        rm -rf "$temp_bqrs_file" "$temp_csv_file"
    fi
    echo
done