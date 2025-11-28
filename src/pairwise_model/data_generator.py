from src.rag_db.db import AutoPatchDB, RAGDataEntry
import os
import json
import argparse

db = AutoPatchDB("<YOUR_API_KEY>")
db.load()


def load_json(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def process_cve(cve_path):
    if os.path.isdir(cve_path):
        code_path = os.path.join(cve_path, "out_v2", "code")
    
        db_entry_path = os.path.join(cve_path, "out_v2", "db_entry.json")
        db_entry_data = load_json(db_entry_path)

        code_file_names = []
        for code_file in os.listdir(code_path):
            if code_file.endswith(".json"):
                code_file_names.append(os.path.splitext(code_file)[0])


        results = {}
        for code_filename in code_file_names:

            code_file_path =  os.path.join(cve_path, "out_v2", "code", f"{code_filename}.json")
            if load_json(code_file_path)["is_vulnerable"] == "N/A":
                continue

            semantics_path = os.path.join(cve_path, "out_v2", "eval_verification", f"semantics_gpt-4o({code_filename}).json")
            semantics_data = load_json(semantics_path)["result"]
            taint_function_path = os.path.join(cve_path, "out_v2", "eval_verification", f"taint_function_gpt-4o({code_filename}).json")
            taint_function_data = load_json(taint_function_path)
            taint_variable_path = os.path.join(cve_path, "out_v2", "eval_verification", f"taint_variable_gpt-4o({code_filename}).json")
            taint_variable_data = load_json(taint_variable_path)

            value = db.search_all(db.extract_keywords(semantics_data), db.embeddings.embed_query(semantics_data), db.calc_vec(taint_variable_data), db.calc_vec(taint_function_data))
            results[code_file_path] = value

        return results

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--cve-path", dest="cve_path", action="store")
    args = parser.parse_args()
    cve_path = args.cve_path

    results = process_cve(cve_path)

    output_json_path = os.path.join(cve_path, "out_v2", "pairwise_data.json")

    with open(output_json_path, "w") as f:
        json.dump(results, f,  indent=4)
    print(f"Completed generation of {cve_path}")