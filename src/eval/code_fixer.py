from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI, OpenAI
import textwrap
import json
import re
import sys
import argparse
import os
import subprocess
import shutil

CODE_QL_PATH = os.path.join(os.path.expanduser("~"), "autopatch", "codeql", "codeql")  # Ensure CodeQL CLI is in PATH or provide full path

class AutoPatchCodeFixer:
    
    def __init__(self, model):

        self.model =model

        if isinstance(self.model, ChatOpenAI):
            # Format instructions
            format_instructions =textwrap.dedent(
                """
                in the following format, including the leading and trailing [START] and [END] tags: 
                [Fixed Source Code START]
                <the fixed source code>
                [Fixed Source Code END]
                """
            ) # dedent end

            # Create chain
            prompt = ChatPromptTemplate([
                    ("system",textwrap.dedent(
                            """
                            You take incomplete or partial C/C++ functions or methods, plus optional compiler or CodeQL error messages, and output a full, compilable source file suitable for CodeQL analysis.

                            Requirements:
                            1. Use the provided error messages to help fix syntax errors, missing types, or missing includes.
                            2. Fix any syntax errors and typos indicated by the errors.
                            3. Stub any undefined structs, classes, or types with minimal declarations.
                            4. Stub undefined functions or methods with empty declarations.
                            5. DON'T include amy headers or libraries (including standard libraries). Just stub the functions or declare variables.
                            6. DOM'T define any macros.
                            7. DON'T change the original logic, flow, or intent of the function.
                            8. Output the complete fixed source code as a standalone .c or .cpp file that compiles with:
                            - gcc -c file.c    (for C)
                            - g++ -c file.cpp  (for C++)

                            Only output the fixed code block. No extra explanation or commentary. Provide the results {format_instructions}
                            """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                        """
                            [Source Code]
                            {source_code}

                            [Error Message]
                            {error_message}
                            """
                        ) # dedent end
                    ),
                    ],
                    partial_variables={"format_instructions":format_instructions}
                )
        else:
            print("Not Supported Model!")
            sys.exit(-1)
    
        self.chain = prompt | model | StrOutputParser()

    def parse(self, output):
        try:
            start_idx = output.find('[Fixed Source Code START]')
            end_idx = output.find('[Fixed Source Code END]')
            if start_idx == -1 or end_idx == -1:
                raise ValueError("Output does not contain the expected tags.")
            parsed_output = output[start_idx + len('[Fixed Source Code START]'): end_idx]

        except Exception as e:
            print("Error while parsing. Need manual parsing.")
            print(e)
            print(output)
            return None

        return parsed_output

    def invoke(self, input):
        return self.chain.invoke(input)



def create_codeql_db(code_path, db_path, language):
    # Ensure the source directory exists
    if not os.path.exists(code_path):
        if os.path.exists(db_path):
            shutil.rmtree(db_path)
        return False, f"[ERROR] code_path does not exist: {code_path}"

    # Run CodeQL database creation command
    compiler_option = "/usr/bin/gcc" if language == "c" else "/usr/bin/g++"

    cmd = [
        CODE_QL_PATH, "database", "create", db_path,
        "--language=c-cpp",
        f"--command={compiler_option} -c {code_path}",
        "--overwrite"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            return True, f"[SUCCESS] CodeQL database created at: {db_path}"
        else:
            error_msg = f"[FAILURE] CodeQL DB creation failed.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            if os.path.exists(db_path):
                shutil.rmtree(db_path)
            return False, error_msg

    except FileNotFoundError:
        if os.path.exists(db_path):
            shutil.rmtree(db_path)
        return False, "[ERROR] CodeQL CLI not found. Is it installed and in PATH?"


FIX_COUNTER = 0
MAX_TRIES = 10
def invoke_code_fixer(model, code, error_message="N/A"):
    global FIX_COUNTER, MAX_TRIES

    parsed_output = None
    while parsed_output is None and FIX_COUNTER < MAX_TRIES:
        input_data = {
            "source_code": code,
            "error_message": error_message
        }

        # Invoke the model
        output = model.invoke(input_data)
        parsed_output = model.parse(output)
        FIX_COUNTER += 1

    return parsed_output

if __name__ == "__main__":
    api_key = "<YOUR_API_KEY>"

    parser = argparse.ArgumentParser(description="AutoPatch Code Fixer")
    parser.add_argument("--code_path", type=str, help="Path to the JSON file containing the code to be fixed", required=True)
    parser.add_argument("--db_path", type=str, help="Path to the codeql db", required=True)
    parser.add_argument("--language", type=str, help="Programming language", required=True)
    args = parser.parse_args()


    # langchain.debug = True
    model = ChatOpenAI(model="gpt-4o", api_key=api_key)
    fixer = AutoPatchCodeFixer(model)

    if args.code_path.endswith(".json"):
        # First Fix
        with open(args.code_path, "r") as f:
            code = json.load(f)["re_implemented_code"]
            code = code.strip().strip("```c").strip("```cpp").strip("```")
    else:
        # Read code from file
        with open(args.code_path, "r") as f:
            code = f.read()

    code = code.strip().strip("```c").strip("```cpp").strip("```")
    fixed_code = invoke_code_fixer(fixer, code, "N/A")
    fixed_code_path = os.path.splitext(args.code_path)[0] + "_fixed." + args.language
    db_path = args.db_path
    if fixed_code is None:
        print("[ERROR] Failed to fix code. Exiting.")
        if os.path.exists(fixed_code_path):
            os.remove(fixed_code_path)
        if os.path.exists(db_path):
            shutil.rmtree(db_path)
        sys.exit(1)
    else:
        with open(fixed_code_path, "w") as f:
            f.write(fixed_code)

    # Iteratively create CodeQL database until successful
    while True:
        success, message = create_codeql_db(fixed_code_path, db_path, args.language)
        if success:
            print(message)
            break
        else:
            print("[ERROR] Failed to create CodeQL database. Retrying...")
            print(message)
            print()
            fixed_code = invoke_code_fixer(fixer, fixed_code, message)
            if fixed_code is None:
                print("[ERROR] Failed to fix code. Exiting.")
                if os.path.exists(fixed_code_path):
                    os.remove(fixed_code_path)
                if os.path.exists(db_path):
                    shutil.rmtree(db_path)
                sys.exit(1)
            else:
                with open(fixed_code_path, "w") as f:
                    f.write(fixed_code)