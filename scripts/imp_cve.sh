#!/bin/bash

# Path to the root of CVE-list
cve_root="CVE-list/"

# Re-create DB table
python src/main.py -i


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
        input_file="$cve_dir/out_v2/db_entry.json"

        echo "Running command for $cve_dir..."

        wait_for_jobs
        # Run the command
        python src/main.py -ic "$input_file" &

        echo "Completed for $cve_dir"
    else
        echo "Skipping $cve_dir (EMPTY_CVE or BACKUP)"
    fi
done