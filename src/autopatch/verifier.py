from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI,OpenAI
import textwrap
import json
import re
import sys

class AutoPatchVerifier:
    
    def __init__(self, model):

        self.model =model

        if isinstance(self.model, ChatOpenAI):
            # Format instructions
            format_instructions =textwrap.dedent(
                """
                in the following schema, including the leading and trailing "```json" and "```" 
                ```json
                {
                        "result": boolean,  // the result of vulnerability verification (true = the vulnerability exists, false = the vulnerability does not exist)
                        "cot" :  the thinking process for the vulnerability verification (Step 1)
                        "root_cause": string // the root cause of the vulnerability of {example_target_cwe_type} wihtin [Target Code] (Step 2)
                        
                }
                ```
                """
            ) # dedent end

            # Create chain
            prompt = ChatPromptTemplate([
                    ("system",textwrap.dedent(
                            """
                            You are an expert software security engineer. Your goal is to analyse user-provided [Target Code] and verify if a vulnerability of {example_target_cwe_type} similar to {example_target_cve_id} exists. To verify if a vulnerability similar to {example_target_cve_id} exists, you will mainly focus on the following [Checklist for {example_target_cve_id}], where mapping from actual variables to each symbolic variables/functions in [Checklist for {example_target_cve_id}] should be provided by user with [Variable Mapping] and [Function Mapping].
                            
                            [Checklist for {example_target_cve_id}]
                            {example_anonymized_target_checklist}
                            
                            Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                            1) Based on [Checklist for {example_target_cve_id}] along with the user-provided [Variable Mapping] and [Function Mapping], verify if {example_target_cwe_type} similar to {example_target_cve_id} exists in [Target Code]
                            2) Based on the vulnerability verification process from Step 1, identify the root cause of {example_target_cwe_type} wihtin [Target Code].
                            3) Provide the results {format_instructions}
                            """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                        """
                            [Supplementary Code]
                            None

                            [Variable Mapping]
                            {example_target_vulnerability_related_variable_mapping}

                            [Function Mapping]
                            {example_target_vulnerability_related_function_mapping}

                            [Target Code]
                            {example_target_code}
                            """
                        ) # dedent end
                    ),
                    ("ai", textwrap.dedent(
                            """
                            Now, I will analyse user-provided [Target Code] and verify if a vulnerability of {example_target_cwe_type} similar to {example_target_cve_id} exists. Then, I will provide the results {format_instructions}

                            Let's think step-by-step.

                            Step 1. Verify if [Target Code] has {example_target_cwe_type} similar to {example_target_cve_id}.
                            {example_target_verification_cot}
                            
                            Step 2. Identify the root cause of {example_target_cwe_type} wihtin [Target Code].
                            {example_target_root_cause}

                            Step 3. Provide the results.
                            ```json
                            {{
                                "result": true,
                                "cot": {example_target_verification_cot_json}
                                "root_cause": {example_target_root_cause_json}
                            }}
                            ```
                            """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                            """
                            [Supplementary Code]
                            {target_supplementary_code}

                            [Variable Mapping]
                            {target_vulnerability_related_variable_mapping}

                            [Function Mapping]
                            {target_vulnerability_related_function_mapping}

                            [Target Code]
                            {target_code}
                            """
                        ) # dedent end
                    )
                    ],
                    partial_variables={"format_instructions":format_instructions}
                )     

        elif isinstance(self.model, OpenAI):
            # Format instructions
            format_instructions =textwrap.dedent(
                """
                in the following schema, including the leading and trailing "```json" and "```" 
                ```json
                {
                        "result": boolean,  // the result of vulnerability verification (true = the vulnerability exists, false = the vulnerability does not exist)
                        "cot" :  the thinking process for the vulnerability verification (Step 1)
                        "root_cause": string // the root cause of the vulnerability of {example_target_cwe_type} wihtin [Target Code] (Step 2)
                        
                }
                ```
                """
            ) # dedent end

            # Create chain
            prompt = ChatPromptTemplate([
                    ("system",textwrap.dedent(
                            """
                            You are an expert software security engineer. Your goal is to analyse user-provided [Target Code] and verify if a vulnerability of {example_target_cwe_type} similar to {example_target_cve_id} exists. To verify if a vulnerability similar to {example_target_cve_id} exists, you will mainly focus on the following [Checklist for {example_target_cve_id}], where mapping from actual variables to each symbolic variables/functions in [Checklist for {example_target_cve_id}] should be provided by user with [Variable Mapping] and [Function Mapping].
                            
                            [Checklist for {example_target_cve_id}]
                            {example_anonymized_target_checklist}
                            
                            Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                            1) Based on [Checklist for {example_target_cve_id}] along with the user-provided [Variable Mapping] and [Function Mapping], verify if {example_target_cwe_type} similar to {example_target_cve_id} exists in [Target Code]
                            2) Based on the vulnerability verification process from Step 1, identify the root cause of {example_target_cwe_type} wihtin [Target Code].
                            3) Provide the results {format_instructions}
                            """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                        """
                            [Supplementary Code]
                            None

                            [Variable Mapping]
                            {example_target_vulnerability_related_variable_mapping}

                            [Function Mapping]
                            {example_target_vulnerability_related_function_mapping}

                            [Target Code]
                            {example_target_code}
                            """
                        ) # dedent end
                    ),
                    ("ai", textwrap.dedent(
                            """
                            Now, I will analyse user-provided [Target Code] and verify if a vulnerability of {example_target_cwe_type} similar to {example_target_cve_id} exists. Then, I will provide the results {format_instructions}

                            Let's think step-by-step.

                            Step 1. Verify if [Target Code] has {example_target_cwe_type} similar to {example_target_cve_id}.
                            {example_target_verification_cot}
                            
                            Step 2. Identify the root cause of  {example_target_cwe_type} wihtin [Target Code].
                            {example_target_root_cause}

                            Step 3. Provide the results.
                            ```json
                            {{
                                "result": true,
                                "cot": {example_target_verification_cot_json},
                                "root_cause": {example_target_root_cause_json}
                            }}
                            ```
                            """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                            """
                            [Supplementary Code]
                            {target_supplementary_code}

                            [Variable Mapping]
                            {target_vulnerability_related_variable_mapping}

                            [Function Mapping]
                            {target_vulnerability_related_function_mapping}

                            [Target Code]
                            {target_code}
                            """
                        ) # dedent end
                    ),
                    ("ai", textwrap.dedent(
                            """
                            Now, I will analyse user-provided [Target Code] and verify if a vulnerability of {example_target_cwe_type} similar to {example_target_cve_id} exists. Then, I will provide the results {format_instructions}

                            Let's think step-by-step.

                            Step 1. Verify if [Target Code] has {example_target_cwe_type} similar to {example_target_cve_id}.
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
        # Now parse using JSON (or regex)
        json_output = None
        json_output_text = None
        try:
            json_output_text = re.findall(r'```json\s*(\{.*?\})\s*```', output, re.DOTALL)[-1].strip()
            json_output = json.loads(json_output_text)
        except Exception as e:
            print(e)
            print("LLM output not directly JSON. Need manual parsing.")
            print(output)
            if json_output_text:
                print("=========================Parsed=====================")
                print(json_output_text)
            return None

        return json_output

    def invoke(self, input):
        return self.chain.invoke(input)