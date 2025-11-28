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
MAX_JOBS=2  # adjust based on your CPU/memory capacity
# Function to manage background jobs
wait_for_jobs() {
    while (( $(jobs -r | wc -l) >= MAX_JOBS )); do
        sleep 1
    done
}

# Determine if this model should run in parallel
if [[ "$model" == "gpt-4o" || "$model" == "o3-mini" || "$model" == "deepseek-r1" ]]; then
  use_parallel=true
else
  use_parallel=false
fi


# Determine if this model should run in parallel
if [[ "$model" == "gpt-4o" || "$model" == "o3-mini" ]]; then
  MAX_JOBS=2
else
  MAX_JOBS=5
fi

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

            db_search_file="$cve_dir""out_v2/eval_verification/db_search_$model($code_filename).json"
            inputs="$code_file,$db_search_file"

            # Check if the output directory already exists
            if [ -f "$output_dir/verify_$model($code_filename).json" ]; then
                echo "Skipping $cve_dir because verify_$model($code_filename).json exists."
                continue  # Skip to the next iteration
            fi

            echo "Running command for $code_file..."

            if $use_parallel; then
                wait_for_jobs
                python src/main.py -ev5 "$inputs" -o "$output_dir" -m "$model" &
            else
                python src/main.py -ev5 "$inputs" -o "$output_dir" -m "$model"
                if [ $? -eq 255 ]; then
                    echo "Python script exited with -1, stopping the process."
                    break
                fi
            fi

            # Check if Python script exited with -1 (indicating failure)
            if [ $? -eq 255 ]; then
                echo "Python script exited with -1, stopping the process."
                break  # Exit the loop and stop the script
            fi

        done

        echo "Completed for $cve_dir"
    else
        echo "Skipping $cve_dir (EMPTY_CVE or BACKUP)"
    fi
done