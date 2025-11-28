# AutoPatch
AutoPatch: Multi-Agent Framework for Patching Real-World CVE Vulnerabilities

### How to Run Evaluation
1. Change <YOUR_API_KEY> fields to your openai api key

2. Initialize DB
- install PostgreSQL and initialize as follows
    - DB_USER = "autopatch"
    - DB_PASSWORD = "autopatch!1234"
    - DB_NAME = "autopatch_db"
- load contents to the DB
    ```
    $ cd autopatch
    $ ./scripts/imp_cve.sh
    ```

3. Run evaluation scripts
- For AutoPatch
    ```
    $ cd autopatch
    $ ./scripts/ev.sh <gpt-4o | o3-mini | deepseek-r1>
    $ ./scripts/ep.sh <gpt-4o | o3-mini | deepseek-r1>
    ```
- For Baseline
    ```
    $ cd autopatch
    # For Verification
    $ ./scripts/ebv.sh
    # For Patch
    $ ./scripts/ebp.sh
    ```
- For CWE One-Shot
    ```
    $ cd autopatch
    # For Verification
    $ ./scripts/esv.sh
    # For Patch
    $ ./scripts/esp.sh
    ```

### How to Add New CVE 
- TODO

### How to Verify and Patch a specific code 
- TODO