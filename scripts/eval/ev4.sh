#!/bin/bash

# Path to the root of CVE-list
cve_root="CVE-list/"
model="$1"

if [[ "$model" != "gpt-4o" && "$model" != "o3-mini" && "$model" != "deepseek-r1"  ]]; then
  echo "Invalid model: $model"
  echo "Valid options are: gpt-4o, o3-mini, deepseek-r1"
  exit 1
fi

job_count=0
MAX_JOBS=16  # adjust based on your CPU/memory capacity
# Function to manage background jobs
wait_for_jobs() {
    while (( $(jobs -r | wc -l) >= MAX_JOBS )); do
        sleep 1
    done
}

# Loop through all directories under CVE-list
for cve_dir in "$cve_root"*/; do
    # Check if it's a directory and not EMPTY_CVE or BACKUP
    if [ -d "$cve_dir" ] && [[ "$cve_dir" != *"EMPTY_CVE"* ]] && [[ "$cve_dir" != *"BACKUP"* ]]; then
        # Define input and output paths for the command
        for code_file in "$cve_dir"out_v2/code/*.json; do
            if jq -e 'has("is_vulnerable")' "$code_file" >/dev/null; then
                value=$(jq -r '.is_vulnerable' "$code_file")
                if [ "$value" == "N/A" ]; then
                    echo "Skipping because $code_file has is_vulnerable set to N/A"
                    continue
                fi
            fi

            output_dir="$cve_dir/out_v2/eval_verification"

            code_filename=$(basename "$code_file")
            code_filename="${code_filename%.*}"

            semantics_file="$cve_dir"out_v2/eval_verification/semantics_"$model($code_filename).json"
            taint_variable_file="$cve_dir"out_v2/eval_verification/taint_variable_"$model($code_filename).json"
            taint_function_file="$cve_dir"out_v2/eval_verification/taint_function_"$model($code_filename).json"
            inputs="$code_file,$semantics_file,$taint_variable_file,$taint_function_file"

            # Check if the output directory already exists
            if [ -f "$output_dir/db_search_$model($code_filename).json" ]; then
                echo "Skipping $cve_dir because db_search_$model($code_filename).json exists."
                continue  # Skip to the next iteration
            fi

            echo "Running command for $code_file..."

            wait_for_jobs

            python src/main.py -ev4 "$inputs" -o "$output_dir" -m "$model" &

        done

        echo "Completed for $cve_dir"
    else
        echo "Skipping $cve_dir (EMPTY_CVE or BACKUP)"
    fi
done