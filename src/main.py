from autopatch.patcher import AutoPatchPatcher
from autopatch.taint_function_analyzer import AutoPatchTaintFunctionAnalyzer
from autopatch.taint_variable_analyzer import AutoPatchTaintVariableAnalyzer
from autopatch.semantic_analyzer import AutoPatchSemanticAnalyzer
from autopatch.verifier import AutoPatchVerifier
from rag_db.db import AutoPatchDB, RAGDataEntry
from rag_db.semantic_analyzer import AutoPatchDBSemanticAnalyzer
from rag_db.taint_function_analysis import AutoPatchDBTaintFunctionAnalyser
from rag_db.taint_variable_analysis import AutoPatchDBTaintVariableAnalyser
from rag_db.verification_cot_generator import AutoPatchDBVerificaitonCoTGenerator
from rag_db.patch_cot_generator import AutoPatchDBPatchCoTGenerator
from langchain_openai import ChatOpenAI,OpenAI
from langchain_ollama import ChatOllama
from langchain_community.callbacks import get_openai_callback
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from transformers import pipeline
from langchain_huggingface import HuggingFacePipeline
from eval.baseline_verifier import AutoPatchBaselineVerifier
from eval.baseline_patcher import AutoPatchBaselinePatcher
from eval.simple_cwe_verifier import AutoPatchSimpleCWEVerifier
from eval.simple_cwe_patcher import AutoPatchSimpleCWEPatcher
from dataclasses import dataclass, asdict
import textwrap
from langchain_core.prompts import ChatPromptTemplate
import json
import argparse
import sys
import csv

import os

api_key = "<YOUR_API_KEY>"
MAX_QUERY_ITER = 20
MAX_PATCH_ITER = 20

class AutoPatcher:
    def __init__(self, model, db, mode = "all"):
        self.model = model
        self.db = db

        if mode == "all":
            # To run
            self.taint_variable_analyzer = AutoPatchTaintVariableAnalyzer(model)
            self.taint_function_analyzer = AutoPatchTaintFunctionAnalyzer(model)
            self.semantic_analyzer = AutoPatchSemanticAnalyzer(model)
            self.verifier = AutoPatchVerifier(model)
            self.patcher = AutoPatchPatcher(model)

            # To generate db entries
            self.db_semantic_analyzer = AutoPatchDBSemanticAnalyzer(model)
            self.db_taint_function_analyzer = AutoPatchDBTaintFunctionAnalyser(model)
            self.db_taint_variable_analyzer = AutoPatchDBTaintVariableAnalyser(model)
            self.db_verification_cot_generator = AutoPatchDBVerificaitonCoTGenerator(model)
            self.db_patch_cot_generator = AutoPatchDBPatchCoTGenerator(model)

        elif mode == "gen_cve":
            # To generate db entries
            self.db_semantic_analyzer = AutoPatchDBSemanticAnalyzer(model)
            self.db_taint_function_analyzer = AutoPatchDBTaintFunctionAnalyser(model)
            self.db_taint_variable_analyzer = AutoPatchDBTaintVariableAnalyser(model)
            self.db_verification_cot_generator = AutoPatchDBVerificaitonCoTGenerator(model)
            self.db_patch_cot_generator = AutoPatchDBPatchCoTGenerator(model)
        elif mode == "gen_cve_finetuning_cost":
            self.finetuning_cost_analyzer = model
        elif mode == "imp_cve":
            pass
        elif mode == "eval_verification_1":
            self.semantic_analyzer = AutoPatchSemanticAnalyzer(model)
        elif mode == "eval_verification_2":
            self.taint_variable_analyzer = AutoPatchTaintVariableAnalyzer(model)       
        elif mode == "eval_verification_3":
            self.taint_function_analyzer = AutoPatchTaintFunctionAnalyzer(model)
        elif mode == "eval_verification_4":
            pass
        elif mode == "eval_verification_5":
            self.verifier = AutoPatchVerifier(model)
        elif mode == "eval_patch_v2":
            self.verifier = AutoPatchVerifier(model)
            self.patcher = AutoPatchPatcher(model)
        elif mode == "eval_base_verification":
            self.base_verifier = AutoPatchBaselineVerifier(model)
        elif mode == "eval_base_patch":
            self.base_verifier = AutoPatchBaselineVerifier(model)
            self.base_patcher = AutoPatchBaselinePatcher(model)
        elif mode == "eval_simple_cwe_verification":
            self.simple_cwe_verifier = AutoPatchSimpleCWEVerifier(model)
        elif mode == "eval_simple_cwe_patch":
            self.simple_cwe_patcher = AutoPatchSimpleCWEPatcher(model)
            self.simple_cwe_verifier = AutoPatchSimpleCWEVerifier(model)

        # Data tracking
        self.data = {}
    
    ##################################
    # General AutoPatch Operations
    ##################################
    def process_all(self, user_data):
        self.data["user_data"] = user_data

        self.implement()
        print("Implement DONE!")

        self.taint_variable_analysis()
        print("Taint-Variable-Analysis DONE!") 

        self.taint_function_analysis()
        print("Taint-Function-Analysis DONE!") 

        self.semantic_analysis()
        print("Semantic-Analysis DONE!")
        
        self.db_search()
        print("DB Search DONE!")  

        self.process_mapping()
        print("process_mapping DONE!")  

        self.verify()
        print("Verificaiton DONE!")

        if not self.data["verify_result"]["result"]:
            print("The implemented code does not have vulnerability!")
            return None

        self.patch()
        print("Patch DONE!")

        # reset data
        self.data = {}

        return self.data["patch_result"]

    def taint_variable_analysis(self):
        # Taint-Analysis 
        taint_variable_analyzer_input = {
            "target_code":self.data["implement_result"]["result"], 
            "supplementary_code": self.data["user_data"]["supplementary_code"],
            "data_flow": self.data["user_data"]["data_flow"],
        }
        parsed_taint_variable_analyzer_output = None
        count = 0
        while parsed_taint_variable_analyzer_output is None and count < MAX_QUERY_ITER:
            raw_taint_variable_analyzer_output = self.taint_variable_analyzer.invoke(taint_variable_analyzer_input)
            parsed_taint_variable_analyzer_output = self.taint_variable_analyzer.parse(raw_taint_variable_analyzer_output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)


        self.data["taint_variable_analysis_result"] = parsed_taint_variable_analyzer_output

    def taint_function_analysis(self):
        # Taint-Analysis 
        taint_function_analyzer_input = {
            "target_code":self.data["implement_result"]["result"], 
            "supplementary_code": self.data["user_data"]["supplementary_code"],
            "data_flow": self.data["user_data"]["data_flow"],
        }

        parsed_taint_function_analyzer_output = None
        count = 0
        while parsed_taint_function_analyzer_output is None and count < MAX_QUERY_ITER:
            raw_taint_function_analyzer_output = self.taint_function_analyzer.invoke(taint_function_analyzer_input)
            parsed_taint_function_analyzer_output = self.taint_function_analyzer.parse(raw_taint_function_analyzer_output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        self.data["taint_function_analysis_result"] = parsed_taint_function_analyzer_output

    def semantic_analysis(self):
        # Semantic-Analysis 
        semantic_analyzer_input = {
            "target_code":self.data["implement_result"]["result"], 
            "supplementary_code": self.data["user_data"]["supplementary_code"],
        }

        parsed_semantic_analyzer_output = None
        count = 0
        while parsed_semantic_analyzer_output is None and count < MAX_QUERY_ITER:
            raw_semantic_analyzer_output = self.semantic_analyzer.invoke(semantic_analyzer_input)
            parsed_semantic_analyzer_output = self.semantic_analyzer.parse(raw_semantic_analyzer_output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)
    
        self.data["semantic_analysis_result"] = parsed_semantic_analyzer_output
    

    def db_search(self):
        # DB-Search
        best_match_rag_entry, verification_var_mapping, verification_func_mapping, user_code_semantics_keywords, semantic_cosine_score, semantic_jaccard_score = db.search(
            self.data["semantic_analysis_result"]["result"],
            self.data["taint_variable_analysis_result"],
            self.data["taint_function_analysis_result"]
        )

        self.data["db_search_result"] = {
            "best_match_rag_entry": best_match_rag_entry,
            "verification_var_mapping": verification_var_mapping,
            "verification_func_mapping": verification_func_mapping,
            "user_code_semantics_keywords": user_code_semantics_keywords,
            "semantic_cosine_score": semantic_cosine_score,
            "semantic_jaccard_score": semantic_jaccard_score
        }
    
    def process_mapping(self):
        ## Symbolic Description
        best_match_rag_entry_vulnerability_related_variable_names = self.data["db_search_result"]["best_match_rag_entry"].vulnerability_related_variables.keys()
        example_anonymized_target_checklist = self.data["db_search_result"]["best_match_rag_entry"].vulnerability_checklist
        example_anonymized_target_fix_list = self.data["db_search_result"]["best_match_rag_entry"].fix_list
        example_target_vulnerability_related_variable_mapping = {}
        target_vulnerability_related_variable_mapping = {}
        for counter, var_name in enumerate(best_match_rag_entry_vulnerability_related_variable_names):
            if var_name not in self.data["db_search_result"]["verification_var_mapping"]:
                continue
            new_var_name = "variable_"+str(counter)
            example_anonymized_target_checklist = example_anonymized_target_checklist.replace(var_name, new_var_name)
            example_anonymized_target_fix_list = example_anonymized_target_fix_list.replace(var_name, new_var_name)
            example_target_vulnerability_related_variable_mapping[new_var_name] = var_name
            target_vulnerability_related_variable_mapping[new_var_name] = self.data["db_search_result"]["verification_var_mapping"][var_name]["mapped_name"]


        best_match_rag_entry_vulnerability_related_function_names = self.data["db_search_result"]["best_match_rag_entry"].vulnerability_related_functions.keys()
        example_target_anonymized_vulnerability_related_functions = {}
        example_target_vulnerability_related_function_mapping = {}
        target_vulnerability_related_function_mapping = {}
        for counter, func_name in enumerate(best_match_rag_entry_vulnerability_related_function_names):
            if func_name not in self.data["db_search_result"]["verification_func_mapping"]:
                continue
            new_func_name = "function_"+str(counter)
            example_anonymized_target_checklist = example_anonymized_target_checklist.replace(func_name, new_func_name)
            example_anonymized_target_fix_list = example_anonymized_target_fix_list.replace(func_name, new_func_name)
            example_target_anonymized_vulnerability_related_functions[new_func_name] = self.data["db_search_result"]["best_match_rag_entry"].vulnerability_related_functions[func_name]["raw"]
            example_target_vulnerability_related_function_mapping[new_func_name] = func_name
            target_vulnerability_related_function_mapping[new_func_name] = self.data["db_search_result"]["verification_func_mapping"][func_name]["mapped_name"]



        self.data["example_anonymized_target_checklist"] = example_anonymized_target_checklist
        self.data["example_anonymized_target_fix_list"] = example_anonymized_target_fix_list

        self.data["example_target_vulnerability_related_variable_mapping"] = example_target_vulnerability_related_variable_mapping
        self.data["example_target_vulnerability_related_function_mapping"] = example_target_vulnerability_related_function_mapping
        self.data["target_vulnerability_related_variable_mapping"] = target_vulnerability_related_variable_mapping
        self.data["target_vulnerability_related_function_mapping"] = target_vulnerability_related_function_mapping

    def verify(self):
        # Verification
        verifier_input = {
                "example_target_cwe_type":self.data["db_search_result"]["best_match_rag_entry"].cwe_type,
                "example_target_cve_id": self.data["db_search_result"]["best_match_rag_entry"].cve_id,
                "example_anonymized_target_checklist":self.data["example_anonymized_target_checklist"], 
                "example_target_vulnerability_related_variable_mapping":self.data["example_target_vulnerability_related_variable_mapping"], 
                "example_target_vulnerability_related_function_mapping":self.data["example_target_vulnerability_related_function_mapping"], 
                "example_target_code":self.data["db_search_result"]["best_match_rag_entry"].original_code,
                "example_target_root_cause":self.data["db_search_result"]["best_match_rag_entry"].root_cause, 
                "example_target_root_cause_json":json.dumps(self.data["db_search_result"]["best_match_rag_entry"].root_cause), 
                "example_target_verification_cot":self.data["db_search_result"]["best_match_rag_entry"].verification_cot,
                "example_target_verification_cot_json": json.dumps(self.data["db_search_result"]["best_match_rag_entry"].verification_cot),
                "target_supplementary_code":self.data["user_data"]["supplementary_code"], 
                "target_vulnerability_related_variable_mapping":self.data["target_vulnerability_related_variable_mapping"], 
                "target_vulnerability_related_function_mapping":self.data["target_vulnerability_related_function_mapping"], 
                "target_code":self.data["implement_result"]["result"], 
        }

        parsed_verifier_output = None
        count = 0
        while parsed_verifier_output is None and count < MAX_QUERY_ITER:
            raw_verifier_output = self.verifier.invoke(verifier_input)
            parsed_verifier_output = self.verifier.parse(raw_verifier_output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        self.data["verify_result"] = parsed_verifier_output
       

    def patch(self):
        # Patch

        patch_input = {
                "example_target_cwe_type":self.data["db_search_result"]["best_match_rag_entry"].cwe_type,
                "example_target_cve_id": self.data["db_search_result"]["best_match_rag_entry"].cve_id,
                "example_anonymized_target_fix_list":self.data["example_anonymized_target_fix_list"], 
                "example_target_supplementary_code":self.data["db_search_result"]["best_match_rag_entry"].supplementary_code,
                "example_target_vulnerability_related_variable_mapping":self.data["example_target_vulnerability_related_variable_mapping"], 
                "example_target_vulnerability_related_function_mapping":self.data["example_target_vulnerability_related_function_mapping"], 
                "example_target_root_cause":self.data["db_search_result"]["best_match_rag_entry"].root_cause, 
                "example_target_code":self.data["db_search_result"]["best_match_rag_entry"].original_code, 
                "example_target_patch_cot":self.data["db_search_result"]["best_match_rag_entry"].verification_cot,
                "example_target_vuln_patch":self.data["db_search_result"]["best_match_rag_entry"].vuln_patch, 
                "target_supplementary_code":self.data["user_data"]["supplementary_code"], 
                "target_vulnerability_related_variable_mapping":self.data["target_vulnerability_related_variable_mapping"], 
                "target_vulnerability_related_function_mapping":self.data["target_vulnerability_related_function_mapping"], 
                "target_root_cause":self.data["verify_result"]["root_cause"], 
                "target_code":self.data["implement_result"]["result"], 
        }

        parsed_patcher_output = None
        count = 0
        while parsed_patcher_output is None and count < MAX_QUERY_ITER:
            raw_patcher_output = self.patcher.invoke(patch_input)
            parsed_patcher_output = self.patcher.parse(raw_patcher_output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        self.data["patch_result"] = parsed_patcher_output

    ##################################
    # RAG DB Operations
    ##################################
    def gen_data_flow_dict(self, file_path):
        dataflow_dict = {}

        with open(file_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for src, dst in reader:
                if src not in dataflow_dict:
                    dataflow_dict[src] = []
                dataflow_dict[src].append(dst)
        return dataflow_dict


    def gen_cve(self, cve_path):

        cve_info_path = cve_path + "/info.json"
        supplementary_code_path = cve_path + "/supplementary_code.txt"
        original_code_path = cve_path + "/original_code.txt"
        vuln_patch_path = cve_path + "/vuln_patch.txt"
        data_flow_path = cve_path + "/out_v2/original_code_data_flow.csv"

        with open(cve_info_path) as f:
            cve_info = json.load(f)

        with open(supplementary_code_path) as f:
            supplementary_code = f.read()

        with open(original_code_path) as f:
            original_code = f.read()

        with open(vuln_patch_path) as f:
            vuln_patch = f.read()
        
        data_flow = self.gen_data_flow_dict(data_flow_path)
        
        self.data["cve_data"] = {
            "cve_info": cve_info,
            "supplementary_code":supplementary_code,
            "original_code":original_code,
            "vuln_patch":vuln_patch,
            "data_flow": data_flow,
        }

        with get_openai_callback() as cb:
            self.db_semantic_analyze()
            db_semantic_analyze_statistics = {
                "total_token": cb.total_tokens,
                "prompt_token": cb.prompt_tokens,
                "completion_token":cb.completion_tokens,
                "total_cost": cb.total_cost
            }
            print("db_semantic_analyze DONE!")

        with get_openai_callback() as cb:
            self.db_verification_cot_generate()
            db_verification_cot_generate_statistics = {
                "total_token": cb.total_tokens,
                "prompt_token": cb.prompt_tokens,
                "completion_token":cb.completion_tokens,
                "total_cost": cb.total_cost
            }
            print("db_verification_cot_generate DONE!")

        with get_openai_callback() as cb:
            self.db_taint_variable_analysis()
            db_taint_variable_analysis_statistics = {
                "total_token": cb.total_tokens,
                "prompt_token": cb.prompt_tokens,
                "completion_token":cb.completion_tokens,
                "total_cost": cb.total_cost
            }
            print("db_taint_variable_analysis DONE!")

        with get_openai_callback() as cb:
            self.db_taint_function_analysis()
            db_taint_function_analysis_statistics = {
                "total_token": cb.total_tokens,
                "prompt_token": cb.prompt_tokens,
                "completion_token":cb.completion_tokens,
                "total_cost": cb.total_cost
            }
            print("db_taint_function_analysis DONE!")

        
        with get_openai_callback() as cb:
            self.db_patch_cot_generate()
            db_patch_cot_generate_statistics = {
                "total_token": cb.total_tokens,
                "prompt_token": cb.prompt_tokens,
                "completion_token":cb.completion_tokens,
                "total_cost": cb.total_cost
            }
            print("db_patch_cot_generate DONE!")


        # consolidate data
        out_data = {
            "cwe_type": cve_info["cwe_id"],
            "cve_id": cve_info["cve_id"],
            "supplementary_code": supplementary_code,
            "original_code": original_code,
            "vuln_patch": vuln_patch,
            "function_name": cve_info["function_name"],
            "function_prototype": cve_info["function_prototype"],
            "code_semantics": self.data["semantic_analyze_result"]["result"],
            "vulnerability_checklist": self.data["verification_cot_generate_result"]["vulnerability_checklist"],
            "safe_verification_cot": self.data["verification_cot_generate_result"]["safe_cot"],
            "verification_cot": self.data["verification_cot_generate_result"]["cot"],
            "vulnerability_related_variables": self.data["taint_variable_analysis_result"],
            "vulnerability_related_functions": self.data["taint_function_analysis_result"],
            "root_cause": self.data["verification_cot_generate_result"]["root_cause"],

            "patch_cot": self.data["patch_cot_generate_result"]["cot"],
            "fix_list":self.data["patch_cot_generate_result"]["fix_list"]
        }

        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        with open(output_path + "/db_entry.json", "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("db entry creation DONE!")

        # consolidate data
        out_data = {
            "db_semantic_analyze_statistics": db_semantic_analyze_statistics,
            "db_taint_variable_analysis_statistics": db_taint_variable_analysis_statistics,
            "db_taint_function_analysis_statistics": db_taint_function_analysis_statistics,
            "db_verification_cot_generate_statistics": db_verification_cot_generate_statistics,
            "db_patch_cot_generate_statistics": db_patch_cot_generate_statistics
        }

        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        with open(output_path + "/db_entry_cost.json", "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("db entry cost creation DONE!")

        # reset data
        self.data = {}

    def gen_cve_finetuning_cost(self, cve_path):

        FINETUNING_EPOCH = 5
        FINETUNING_COST_PER_TOKEN = 0.000025

        re_implementation_dev_requirment_path = cve_path + "out_v2/re_implementation_dev_requirement.json"
        supplementary_code_path = cve_path + "/supplementary_code.txt"
        vuln_patch_path = cve_path + "/vuln_patch.txt"

        with open(re_implementation_dev_requirment_path) as f:
            re_implementation_dev_requirment = json.load(f)

        with open(supplementary_code_path) as f:
            supplementary_code = f.read()

        with open(vuln_patch_path) as f:
            vuln_patch = f.read()


        format_instructions =textwrap.dedent(
            """
            in the following format, including the leading and trailing "```" and "```" 
            ```
            [Implemented Code START]
            <the implemented code>
            [Implemented Code END]
            ```
            """
        ) # dedent end

        prompt = ChatPromptTemplate([
                ("system",textwrap.dedent(
                        """
                        You are an expert software engineer. Your goal is to implement [Skeleton Code] by filling in the implementation for all "<implement_here>" placeholders in [Skeleton Code]. Then, provide the result {format_instructions}
                        """ 
                    ) # dedent end
                ),
            ("user", textwrap.dedent(
                """
                [Supplementary Code]
                None
                
                [Skeleton Code]
                ```c
                int binary_search(int arr[], int size, int target) {{
                    // Initialize the left boundary of the search space to the beginning of the array
                    // <implement_here>

                    // Initialize the right boundary of the search space to the end of the array
                    // <implement_here>

                    // Continue searching while the left index is less than or equal to the right index
                    while (/* <implement_here> */) {{
                        // Calculate the middle index of the current search space to avoid overflow
                        // <implement_here>

                        // If the element at the middle index is equal to the target, return the index
                        // <implement_here>

                        // If the middle element is less than the target, discard the left half
                        // <implement_here>

                        // If the middle element is greater than the target, discard the right half
                        // <implement_here>
                    }}

                    // If the loop exits, the target was not found; return -1 to indicate failure
                    // <implement_here>
                }} // End of Implementation
                ```
                """) # dedent end   
            ),
            ("ai", textwrap.dedent(
                """
                Now, I will implement [Skeleton Code] and provide the result {format_instructions}

                ```
                [Implemented Code START]
                ```c
                int binary_search(int arr[], int size, int target) {{
                    // Initialize the left boundary of the search space to the beginning of the array
                    int left = 0;

                    // Initialize the right boundary of the search space to the end of the array
                    int right = size - 1;

                    // Continue searching while the left index is less than or equal to the right index
                    while (left <= right) {{
                        // Calculate the middle index of the current search space to avoid overflow
                        int mid = left + (right - left) / 2;

                        // If the element at the middle index is equal to the target, return the index
                        if (arr[mid] == target)
                            return mid;

                        // If the middle element is less than the target, discard the left half
                        else if (arr[mid] < target)
                            left = mid + 1;

                        // If the middle element is greater than the target, discard the right half
                        else
                            right = mid - 1;
                    }}

                    // If the loop exits, the target was not found; return -1 to indicate failure
                    return -1;
                }} // End of Implementation
                ```
                [Implemented Code END]
                ```
                
                """
                ) # dedent end   
            ),
            ("user", textwrap.dedent(
                    """
                    [Supplementary Code]
                    {supplementary_code}
                    
                    [Skeleton Code]
                    {code_description}
                    
                    """
                    ) # dedent end
            ),
            ("ai", textwrap.dedent(
                """
                Now, I will complete [Skeleton Code] and provide the result {format_instructions}


                [Implemented Code START]
                {implemented_code}
                [Implemented Code END]
                
                ```
                """
                )
            )
            ], partial_variables = {
                "format_instructions": format_instructions,
                "supplementary_code": supplementary_code,
                "code_description": re_implementation_dev_requirment["code_description"],
                "implemented_code": vuln_patch
                }
        ).format_messages()


        total_token = self.finetuning_cost_analyzer.get_num_tokens_from_messages(prompt)

        # consolidate data
        out_data = {
            "total_token": total_token,
            "finetuning_cost": total_token* FINETUNING_EPOCH * FINETUNING_COST_PER_TOKEN
        }

        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        with open(output_path + "/cve_finetuning_cost.json", "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("cve_finetuning_cost creation DONE!")

        # reset data
        self.data = {}

    def update_cve(self, cve_path):

        cve_info_path = cve_path + "/info.json"
        supplementary_code_path = cve_path + "/supplementary_code.txt"
        original_code_path = cve_path + "/original_code.txt"
        vuln_patch_path = cve_path + "/vuln_patch.txt"
        db_entry_path = cve_path + "/out_v2/db_entry.json"

        with open(cve_info_path) as f:
            cve_info = json.load(f)

        with open(supplementary_code_path) as f:
            supplementary_code = f.read()

        with open(original_code_path) as f:
            original_code = f.read()

        with open(vuln_patch_path) as f:
            vuln_patch = f.read()

        with open(db_entry_path) as f:
            db_entry = json.load(f)
        
        self.data["cve_data"] = {
            "cve_info": cve_info,
            "supplementary_code":supplementary_code,
            "original_code":original_code,
            "vuln_patch":vuln_patch,
        }
        self.data["verification_cot_generate_result"] = {
            "vulnerability_related_variables": str(list(db_entry["vulnerability_related_variables"].keys())),
            "vulnerability_related_functions": str(list(db_entry["vulnerability_related_functions"].keys())),
            "root_cause": db_entry["root_cause"]
        }

        self.db_patch_cot_generate()
        print("db_patch_cot_generate DONE!")

        db_entry["fix_list"] = self.data["patch_cot_generate_result"]["fix_list"]
        db_entry["patch_cot"] = self.data["patch_cot_generate_result"]["cot"]

        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        with open(db_entry_path, "w") as file:
            json.dump(db_entry, file, indent=4)  # indent=4 makes it more readable
        
        print("db entry update DONE!")

        # reset data
        self.data = {}

    def imp_cve(self, cve_db_entry_path):
        with open(cve_db_entry_path) as f:
            cve_db_entry_data = json.load(f)
        
        cve_db_entry_data["id"] = -1

        cve_db_entry = RAGDataEntry(**cve_db_entry_data)
        self.db.insert_data(cve_db_entry)

        print("db entry insertion DONE!")

    def db_semantic_analyze(self):
        input = {
            "supplementary_code": self.data["cve_data"]["supplementary_code"],
            "target_code": self.data["cve_data"]["original_code"],
        }

        parsed_output = None
        count = 0
        while parsed_output is None and count < MAX_QUERY_ITER:
            output = self.db_semantic_analyzer.invoke(input)
            parsed_output = self.db_semantic_analyzer.parse(output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        self.data["semantic_analyze_result"] = parsed_output            

    def db_verification_cot_generate(self):
        input = {
            "cve_id":self.data["cve_data"]["cve_info"]["cve_id"],
            "cwe_type":self.data["cve_data"]["cve_info"]["cwe_id"], 
            "supplementary_code": self.data["cve_data"]["supplementary_code"],
            "target_code": self.data["cve_data"]["original_code"],
            "vuln_patch":self.data["cve_data"]["vuln_patch"]
        }

        parsed_output = None
        count = 0
        while parsed_output is None and count < MAX_QUERY_ITER:
            output = self.db_verification_cot_generator.invoke(input)
            parsed_output = self.db_verification_cot_generator.parse(output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        if self.data["cve_data"]["cve_info"]["function_name"] in parsed_output["vulnerability_related_functions"]:
            parsed_output["vulnerability_related_functions"].remove(self.data["cve_data"]["cve_info"]["function_name"])

        self.data["verification_cot_generate_result"] = parsed_output
    
    
    def db_patch_cot_generate(self):
        input = {
                "cwe_type":self.data["cve_data"]["cve_info"]["cwe_id"],
                "supplementary_code": self.data["cve_data"]["supplementary_code"],
                "target_code": self.data["cve_data"]["original_code"],
                "root_cause": self.data["verification_cot_generate_result"]["root_cause"],
                "vulnerability_related_functions": self.data["verification_cot_generate_result"]["vulnerability_related_functions"],
                "vulnerability_related_variables": self.data["verification_cot_generate_result"]["vulnerability_related_variables"],
                "vuln_patch":self.data["cve_data"]["vuln_patch"]
        }
        parsed_output = None
        count = 0
        while parsed_output is None and count < MAX_QUERY_ITER:
            output = self.db_patch_cot_generator.invoke(input)
            parsed_output = self.db_patch_cot_generator.parse(output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        self.data["patch_cot_generate_result"] = parsed_output


    def db_taint_variable_analysis(self):
        if len(self.data["verification_cot_generate_result"]["vulnerability_related_variables"]) == 0:
            self.data["taint_variable_analysis_result"] = {}
        else:
            input = {
                    "supplementary_code": self.data["cve_data"]["supplementary_code"],
                    "target_code": self.data["cve_data"]["original_code"],
                    "data_flow": self.data["cve_data"]["data_flow"],
                    "target_variables": self.data["verification_cot_generate_result"]["vulnerability_related_variables"],
            }

            parsed_output = None
            count = 0
            while parsed_output is None and count < MAX_QUERY_ITER:
                output = self.db_taint_variable_analyzer.invoke(input)
                parsed_output = self.db_taint_variable_analyzer.parse(output)
                count+=1
            if count >= MAX_QUERY_ITER:
                sys.exit(-1)
            
            self.data["taint_variable_analysis_result"] = parsed_output


    def db_taint_function_analysis(self):
        if len(self.data["verification_cot_generate_result"]["vulnerability_related_functions"]) == 0:
            self.data["taint_function_analysis_result"] = {}
        else:
            input = {
                    "supplementary_code": self.data["cve_data"]["supplementary_code"],
                    "target_code": self.data["cve_data"]["original_code"],
                    "target_functions": self.data["verification_cot_generate_result"]["vulnerability_related_functions"],
                    "data_flow": self.data["cve_data"]["data_flow"],
            }

            parsed_output = None
            count = 0
            while parsed_output is None and count < MAX_QUERY_ITER:
                output = self.db_taint_function_analyzer.invoke(input)
                parsed_output = self.db_taint_function_analyzer.parse(output)
                count+=1
            if count >= MAX_QUERY_ITER:
                sys.exit(-1)

            self.data["taint_function_analysis_result"] = parsed_output


    ##################################
    # Evaluation(Verificaiton) Operations
    ##################################

    # For verification(semantics)
    def eval_verification_1(self, code_path):
        with open(code_path) as f:
            code = json.load(f)
        self.data["implement_result"] = {
            "result": code["re_implemented_code"]
        }
        self.data["user_data"] = {
            "supplementary_code": code["supplementary_code"]
        }

        self.semantic_analysis()
        print("semantic_analysis DONE!")

        # consolidate data
        out_data = self.data["semantic_analysis_result"]

        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/semantics_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("eval_verification_1 creation DONE!")

        self.data = {}

    # For verification(taint variable)
    def eval_verification_2(self, code_path, data_flow_path):
        with open(code_path) as f:
            code = json.load(f)
        data_flow = self.gen_data_flow_dict(data_flow_path)

        self.data["implement_result"] = {
            "result": code["re_implemented_code"]
        }
        self.data["user_data"] = {
            "supplementary_code": code["supplementary_code"],
            "data_flow": data_flow
        }

        self.taint_variable_analysis()
        print("taint_variable_analysis DONE!")

        # consolidate data
        out_data = self.data["taint_variable_analysis_result"]

        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/taint_variable_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("eval_verification_2 creation DONE!")

        self.data = {}

    # For verification(taint function)
    def eval_verification_3(self, code_path, data_flow_path):
        with open(code_path) as f:
            code = json.load(f)

        data_flow = self.gen_data_flow_dict(data_flow_path)

        self.data["implement_result"] = {
            "result": code["re_implemented_code"]
        }
        self.data["user_data"] = {
            "supplementary_code": code["supplementary_code"],
            "data_flow": data_flow
        }

        self.taint_function_analysis()
        print("taint_function_analysis DONE!")

        # consolidate data
        out_data = self.data["taint_function_analysis_result"]
        
        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/taint_function_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("eval_verification_3 creation DONE!")

        self.data = {}

    # For verification(db_search)
    def eval_verification_4(self, code_path, semantics_path, taint_variable_path, taint_function_path):
        with open(semantics_path) as f:
            semantics = json.load(f)

        with open(taint_variable_path) as f:
            taint_variable = json.load(f)

        with open(taint_function_path) as f:
            taint_function = json.load(f)

        self.data["semantic_analysis_result"] = semantics
        self.data["taint_variable_analysis_result"] = taint_variable
        self.data["taint_function_analysis_result"]= taint_function

        self.db_search()
        print("db_search DONE!")

        # consolidate data
        self.data["db_search_result"]["best_match_rag_entry"].trim_vec()
        self.data["db_search_result"]["best_match_rag_entry"] = asdict(self.data["db_search_result"]["best_match_rag_entry"])
        out_data = self.data["db_search_result"]
        
        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/db_search_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("eval_verification_4 creation DONE!")

        self.data = {}


    # For verification(verify)
    def eval_verification_5(self, code_path, db_search_path):
        
        # Load data from previous phase
        with open(code_path) as f:
            code = json.load(f)

        with open(db_search_path) as f:
            db_search_result = json.load(f)

        self.data["db_search_result"] = db_search_result
        self.data["db_search_result"]["best_match_rag_entry"] = RAGDataEntry(**self.data["db_search_result"]["best_match_rag_entry"])
        self.data["implement_result"] = {
            "result": code["re_implemented_code"]
        }
        self.data["user_data"] = {
            "supplementary_code": code["supplementary_code"]
        }

        # Process variable/function mappings
        self.process_mapping()
        print("process_mapping DONE!")

         # Perform verification
        self.verify()
        print("verify DONE!")

        # consolidate data
        out_data = self.data["verify_result"]
        
        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/verify_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("eval_verification_5 creation DONE!")

        self.data = {}

    ##################################
    # Evaluation(Patch) Operations
    ##################################

    # For patch_v2
    def eval_patch_v2(self, code_path, db_search_path, verify_path):
        
        # Load data from previous phase
        with open(code_path) as f:
            code = json.load(f)

        with open(db_search_path) as f:
            db_search_result = json.load(f)

        with open(verify_path) as f:
            verify_result = json.load(f)

        self.data["db_search_result"] = db_search_result
        self.data["db_search_result"]["best_match_rag_entry"] = RAGDataEntry(**self.data["db_search_result"]["best_match_rag_entry"])
        self.data["implement_result"] = {
            "result": code["re_implemented_code"]
        }
        self.data["user_data"] = {
            "supplementary_code": code["supplementary_code"]
        }
        self.data["verify_result"] = verify_result

        count = 0
        while self.data["verify_result"]["result"] and count < MAX_PATCH_ITER:

            if count == 0:
                # Process variable/function mappings
                self.process_mapping()
                print("process_mapping DONE!")

            # Perform verification
            self.patch()
            print("patch DONE!")
            self.data["implement_result"]["result"] = self.data["patch_result"]["vuln_patch"]

            self.verify()
            print("verify DONE!")

            count +=1

        # consolidate data
        out_data = self.data["patch_result"]
        out_data["patch_count"] = count
        out_data["verification_result"] = self.data["verify_result"]["result"] 
        
        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/patch_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
    
        print("eval_patch_v2 creation DONE!")

        self.data = {}


    ##################################
    # Baseline Evaluation Operations 
    ##################################


    def base_verify(self):
        # Verification
        verifier_input = {
                "cwe_type":self.data["user_data"]["cwe_type"],
                "target_supplementary_code":self.data["user_data"]["supplementary_code"], 
                "target_code":self.data["implement_result"]["result"], 
        }


        parsed_verifier_output = None
        count = 0
        while parsed_verifier_output is None and count < MAX_QUERY_ITER:
            raw_verifier_output = self.base_verifier.invoke(verifier_input)
            parsed_verifier_output = self.base_verifier.parse(raw_verifier_output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        self.data["base_verify_result"] = parsed_verifier_output
       

    # For baseline verification
    def eval_base_verification(self, code_path, info_path):
        with open(code_path) as f:
            code = json.load(f)
        
        with open(info_path) as f:
            info = json.load(f)

        self.data["implement_result"] = {
            "result": code["re_implemented_code"]
        }
        self.data["user_data"] = {
            "supplementary_code": code["supplementary_code"],
            "cwe_type": info["cwe_id"]
        }

        self.base_verify()
        print("base_verify DONE!")

        # consolidate data
        out_data = self.data["base_verify_result"]

        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/verify_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("eval_base_verification creation DONE!")

        self.data = {}


    def base_patch(self):
        # Patch

        patch_input = {
                "cwe_type":self.data["user_data"]["cwe_type"],
                "target_supplementary_code":self.data["user_data"]["supplementary_code"], 
                "target_root_cause":self.data["base_verify_result"]["root_cause"], 
                "target_code":self.data["implement_result"]["result"], 
        }

        parsed_patcher_output = None
        count = 0
        while parsed_patcher_output is None and count < MAX_QUERY_ITER:
            raw_patcher_output = self.base_patcher.invoke(patch_input)
            parsed_patcher_output = self.base_patcher.parse(raw_patcher_output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        self.data["base_patch_result"] = parsed_patcher_output


    # For baseline patch
    def eval_base_patch(self, code_path, info_path, base_verify_result_path):
        with open(code_path) as f:
            code = json.load(f)
        
        with open(info_path) as f:
            info = json.load(f)

        with open(base_verify_result_path) as f:
            base_verify_result = json.load(f)

        self.data["implement_result"] = {
            "result": code["re_implemented_code"]
        }
        self.data["user_data"] = {
            "supplementary_code": code["supplementary_code"],
            "cwe_type": info["cwe_id"]
        }
        self.data["base_verify_result"] = base_verify_result

        count = 0
        while self.data["base_verify_result"]["result"] and count < MAX_PATCH_ITER:
            # Perform patch
            self.base_patch()
            print("base_patch DONE!")
            self.data["implement_result"]["result"] = self.data["base_patch_result"]["vuln_patch"]

            self.base_verify()
            print("base_verify DONE!")

            count +=1

        # consolidate data
        out_data = self.data["base_patch_result"]
        out_data["patch_count"] = count
        out_data["verification_result"] = self.data["base_verify_result"]["result"] 

        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/patch_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("eval_base_patch creation DONE!")

        self.data = {}


    ##################################
    # Simple CWE Evaluation Operations 
    ##################################

    def gen_simple_cwe(self, cwe_path):

        with open(cwe_path) as f:
            cwe_data = json.load(f)
        
        self.data["cwe_data"] = cwe_data
        self.data["cwe_data"]["cwe_type"] = os.path.splitext(os.path.basename(cwe_path))[0]

        self.simple_cwe_verification_cot_generate()
        print("simple_cwe_verification_cot_generate DONE!")

        self.simple_cwe_patch_cot_generate()
        print("simple_cwe_patch_cot_generate DONE!")


        # consolidate data
        out_data = cwe_data
        out_data["verification_cot"] = self.data["simple_cwe_verification_cot_generate_result"]["cot"]
        out_data["root_cause"] = self.data["simple_cwe_verification_cot_generate_result"]["root_cause"]
        out_data["patch_cot"] = self.data["simple_cwe_patch_cot_generate_result"]["cot"]

        # Write back to a JSON file
        with open(cwe_path, "w") as file:
            json.dump(out_data, file, indent=4)
        
        print("gen_simple_cwe creation DONE!")

        # reset data
        self.data = {}


    def simple_cwe_verify(self):
        verifier_input = {
                "cwe_type":self.data["cwe_data"]["cwe_type"],
                "example_target_supplementary_code": self.data["cwe_data"]["supplementary_code"], 
                "example_target_code":self.data["cwe_data"]["target_code"], 
                "example_target_root_cause":self.data["cwe_data"]["root_cause"], 
                "example_target_verification_cot":self.data["cwe_data"]["verification_cot"], 
                "target_supplementary_code":self.data["user_data"]["supplementary_code"], 
                "target_code":self.data["implement_result"]["result"]
        }

        parsed_verifier_output = None
        count = 0
        while parsed_verifier_output is None and count < MAX_QUERY_ITER:
            raw_verifier_output = self.simple_cwe_verifier.invoke(verifier_input)
            parsed_verifier_output = self.simple_cwe_verifier.parse(raw_verifier_output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        self.data["simple_cwe_verify_result"] = parsed_verifier_output
       

    # For baseline verification
    def eval_simple_cwe_verification(self, code_path, cwe_path):
        with open(code_path) as f:
            code_data = json.load(f)

        with open(cwe_path) as f:
            cwe_data = json.load(f)

        self.data["implement_result"] = {
            "result": code_data["re_implemented_code"]
        }
        self.data["user_data"] = {
            "supplementary_code": code_data["supplementary_code"]
        }
        self.data["cwe_data"]  = cwe_data

        self.simple_cwe_verify()
        print("simple_cwe_verify DONE!")

        # consolidate data
        out_data = self.data["simple_cwe_verify_result"]

        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/verify_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("eval_simple_cwe_verification creation DONE!")

        self.data = {}


    def simple_cwe_patch(self):
        # Patch

        patch_input = {
                "cwe_type":self.data["cwe_data"]["cwe_type"],
                "example_target_supplementary_code": self.data["cwe_data"]["supplementary_code"], 
                "example_target_code":self.data["cwe_data"]["target_code"], 
                "example_target_root_cause":self.data["cwe_data"]["root_cause"], 
                "example_target_patch_cot":self.data["cwe_data"]["patch_cot"], 
                "example_target_vuln_patch":self.data["cwe_data"]["vuln_patch"], 
                "target_supplementary_code":self.data["user_data"]["supplementary_code"], 
                "target_root_cause":self.data["simple_cwe_verify_result"]["root_cause"], 
                "target_code":self.data["implement_result"]["result"], 
        }

        parsed_patcher_output = None
        count = 0
        while parsed_patcher_output is None and count < MAX_QUERY_ITER:
            raw_patcher_output = self.simple_cwe_patcher.invoke(patch_input)
            parsed_patcher_output = self.simple_cwe_patcher.parse(raw_patcher_output)
            count+=1
        if count >= MAX_QUERY_ITER:
            sys.exit(-1)

        self.data["simple_cwe_patch_result"] = parsed_patcher_output


    # For simple_cwe patch
    def eval_simple_cwe_patch(self, code_path, cwe_path, simple_cwe_verify_result_path):

        # Load JSON
        with open(code_path) as f:
            code_data = json.load(f)

        with open(cwe_path) as f:
            cwe_data = json.load(f)

        with open(simple_cwe_verify_result_path) as f:
            simple_cwe_verify_result = json.load(f)

        # Prepare Data
        self.data["implement_result"] = {
            "result": code_data["re_implemented_code"]
        }
        self.data["user_data"] = {
            "supplementary_code": code_data["supplementary_code"]
        }
        self.data["simple_cwe_verify_result"] = simple_cwe_verify_result
        self.data["cwe_data"]  = cwe_data

        # Perform Patch-Verification Lopp
        count = 0
        while self.data["simple_cwe_verify_result"]["result"] and count < MAX_PATCH_ITER:
            # Perform patch
            self.simple_cwe_patch()
            print("simple_cwe_patch DONE!")
            self.data["implement_result"]["result"] = self.data["simple_cwe_patch_result"]["vuln_patch"]

            self.simple_cwe_verify()
            print("simple_cwe_verify DONE!")

            count +=1

        # consolidate data
        out_data = self.data["simple_cwe_patch_result"]
        out_data["patch_count"] = count
        out_data["verification_result"] = self.data["simple_cwe_verify_result"]["result"] 
        
        # Writing to a JSON file
        os.makedirs(output_path, exist_ok=True)
        code_filename_no_ext = os.path.splitext(os.path.basename(code_path))[0]
        with open(output_path + "/patch_{}({}).json".format(model_name, code_filename_no_ext), "w") as file:
            json.dump(out_data, file, indent=4)  # indent=4 makes it more readable
        
        print("eval_simple_cwe_patch creation DONE!")

        self.data = {}



output_path = os.getcwd()
model = None
model_name = None

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--init-db", dest="init_db", action="store_true")
    parser.add_argument("-td", "--test-db", dest="test_db", action="store_true")
    parser.add_argument("-o", "--output-path", dest="output_path", action="store")
    parser.add_argument("-r", "--run", dest="run", action="store")
    parser.add_argument("-m", "--model", dest="model", action="store")
    parser.add_argument("-gc", "--gen-cve", dest="gen_cve", action="store")
    parser.add_argument("-gcfc", "--gen-cve-finetuning-cost", dest="gen_cve_finetuning_cost", action="store")
    parser.add_argument("-ic", "--imp-cve", dest="imp_cve", action="store")
    parser.add_argument("-ev1", "--evaluation-verificaiton-1", dest="eval_verification_1", action="store") # verification
    parser.add_argument("-ev2", "--evaluation-verificaiton-2", dest="eval_verification_2", action="store") # verification
    parser.add_argument("-ev3", "--evaluation-verificaiton-3", dest="eval_verification_3", action="store") # verification
    parser.add_argument("-ev4", "--evaluation-verificaiton-4", dest="eval_verification_4", action="store") # verification
    parser.add_argument("-ev5", "--evaluation-verificaiton-5", dest="eval_verification_5", action="store") # verification
    parser.add_argument("-ep-v2", "--evaluation-patch-v2", dest="eval_patch_v2", action="store") # patch

    parser.add_argument("-ebv", "--evaluation-base-verification", dest="eval_base_verification", action="store") # verification
    parser.add_argument("-ebp", "--evaluation-base-patch", dest="eval_base_patch", action="store") # patch
    parser.add_argument("-gsc", "--generate-simple-cwe", dest="gen_simple_cwe", action="store") # verification
    parser.add_argument("-esv", "--evaluation-simple-verification", dest="eval_simple_cwe_verification", action="store") # verification
    parser.add_argument("-esp", "--evaluation-simple-patch-v2", dest="eval_simple_cwe_patch", action="store") # patch

    parser.add_argument("-uc", "--update-cve", dest="update_cve", action="store")


    args = parser.parse_args()

    # Configure result output path
    if args.output_path:
        output_path = args.output_path

    # # Configure temperature
    # if args.eval_reimpl_2 or args.eval_reimpl_2_v2:
    #     temperature = 0.2 # practical temperature for programming
    # else:
    temperature = 0.0

    if args.model:
        model_name = args.model
        if args.model == "gpt-4o":
            model = ChatOpenAI(model="gpt-4o", temperature=temperature, api_key=api_key, top_p = 0.9)
        elif args.model == "o3-mini":
            model = ChatOpenAI(model="o3-mini", api_key=api_key)
        else:
            if args.model == 'llama':
                model_id = "codellama/CodeLlama-13b-Instruct-hf"
                max_tokens = 2000
            elif args.model == 'deepseek-r1':
                model_id="deepseek-ai/DeepSeek-R1-Distill-Qwen-32B"
                max_tokens = 5000 # usually large due to reasoning tokens
            elif args.model == 'deepseek':
                model_id = "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct"
                max_tokens = 2000
            inference_server_url = "http://localhost:8000/v1"
            model = OpenAI(model=model_id, max_tokens = max_tokens, openai_api_key="EMPTY", openai_api_base=inference_server_url, 
                           temperature=temperature, extra_body = {"repetition_penalty":1.2, "top_p": 0.9})
    else:
        model = ChatOpenAI(model="gpt-4o", temperature=temperature, api_key=api_key, top_p = 0.9)
        model_name = "gpt-4o"

    if not args.init_db:
        db = AutoPatchDB(api_key)

    if args.run:
        with open(args.run) as f:
            user_data = json.load(f)

        auto_patcher = AutoPatcher(model, db)
        auto_patcher.process_all(user_data)
        print("run DONE")
    elif args.init_db:
        db = AutoPatchDB("")
        db.create_table()
        print("init_db DONE")
    elif args.test_db:
        db = AutoPatchDB("")
        db.load()
        print(len(db.rag_entries))
    elif args.gen_cve: # generate cve rag entry data & import
        auto_patcher = AutoPatcher(model, db, "gen_cve")
        auto_patcher.gen_cve(args.gen_cve) # cve path
    elif args.gen_cve_finetuning_cost: # generate cve fintuning cost file
        auto_patcher = AutoPatcher(model, db, "gen_cve_finetuning_cost")
        auto_patcher.gen_cve_finetuning_cost(args.gen_cve_finetuning_cost) # cve path
    elif args.update_cve: # generate cve rag entry data & import
        auto_patcher = AutoPatcher(model, db, "gen_cve")
        auto_patcher.update_cve(args.update_cve) # cve path
    elif args.imp_cve: # import cve rag entry data
        auto_patcher = AutoPatcher(model, db, "imp_cve")
        auto_patcher.imp_cve(args.imp_cve) # data_entry.json path
    elif args.eval_verification_1: # operations for verification evaluation 1
        auto_patcher = AutoPatcher(model, db, "eval_verification_1")
        auto_patcher.eval_verification_1(args.eval_verification_1) # <aug_or_re_implementation_code>.json path
    elif args.eval_verification_2: # operations for verification evaluation 2
        auto_patcher = AutoPatcher(model, db, "eval_verification_2")
        path_list = args.eval_verification_2.split(',')
        # Pass as separate arguments using *
        auto_patcher.eval_verification_2(*path_list)
    elif args.eval_verification_3: # operations for verification evaluation 3
        auto_patcher = AutoPatcher(model, db, "eval_verification_3")
        path_list = args.eval_verification_3.split(',')
        # Pass as separate arguments using *
        auto_patcher.eval_verification_3(*path_list)
    elif args.eval_verification_4: # operations for verification evaluation 4
        # Split into list
        auto_patcher = AutoPatcher(model, db, "eval_verification_4")
        path_list = args.eval_verification_4.split(',')
        # Pass as separate arguments using *
        auto_patcher.eval_verification_4(*path_list)
    elif args.eval_verification_5: # operations for verification evaluation 5
        auto_patcher = AutoPatcher(model, db, "eval_verification_5")
        # Split into list
        path_list = args.eval_verification_5.split(',')
        # Pass as separate arguments using *
        auto_patcher.eval_verification_5(*path_list)
     
    elif args.eval_patch_v2:
        auto_patcher = AutoPatcher(model, db, "eval_patch_v2")
        # Split into list
        path_list = args.eval_patch_v2.split(',')
        # Pass as separate arguments using *
        auto_patcher.eval_patch_v2(*path_list)   

    elif args.eval_base_verification:
        auto_patcher = AutoPatcher(model, db, "eval_base_verification")
        # Split into list
        path_list = args.eval_base_verification.split(',')
        auto_patcher.eval_base_verification(*path_list)           
    elif args.eval_base_patch:
        auto_patcher = AutoPatcher(model, db, "eval_base_patch")
        path_list = args.eval_base_patch.split(',')
        auto_patcher.eval_base_patch(*path_list)

    elif args.gen_simple_cwe:
        auto_patcher = AutoPatcher(model, db, "gen_simple_cwe")
        auto_patcher.gen_simple_cwe(args.gen_simple_cwe)
    elif args.eval_simple_cwe_verification:
        auto_patcher = AutoPatcher(model, db, "eval_simple_cwe_verification")
        # Split into list
        path_list = args.eval_simple_cwe_verification.split(',')
        auto_patcher.eval_simple_cwe_verification(*path_list)           
    elif args.eval_simple_cwe_patch:
        auto_patcher = AutoPatcher(model, db, "eval_simple_cwe_patch")
        path_list = args.eval_simple_cwe_patch.split(',')
        auto_patcher.eval_simple_cwe_patch(*path_list) 

    else:
        print("Not Supported Operation")
