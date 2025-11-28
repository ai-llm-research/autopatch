from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI, OpenAI
import textwrap
import json
import re
import sys

class AutoPatchBaselineVerifier:
    
    def __init__(self, model):

        self.model =model

        if isinstance(self.model, ChatOpenAI):
            # Format instructions
            format_instructions =textwrap.dedent(
                """
                in a valid JSON format with the following schema, including the leading and trailing "```json" and "```" 
                ```json
                {
                        "result": boolean,  // the result of vulnerability verification (true = the vulnerability exists, false = the vulnerability does not exist)
                        "cot" : "<the thinking process for the vulnerability verification (Step 1)>",
                        "root_cause": string // the root cause of the vulnerability of {cwe_type} wihtin [Target Code] (Step 2)
                        
                }
                ```
                """
            ) # dedent end

            # Create chain
            prompt = ChatPromptTemplate([
                    ("system",textwrap.dedent(
                            """
                            You are an expert software security engineer. Your goal is to analyse user-provided [Target Code] and verify if a vulnerability of {cwe_type} exists.
                            
                            Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                            1) Verify if {cwe_type} exists in [Target Code]
                            2) Based on the vulnerability verification thinking process from Step 1, identify the root cause of {cwe_type} wihtin [Target Code].
                            3) Provide the results {format_instructions}
                            """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                            """
                            [Supplementary Code]
                            {target_supplementary_code}

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
                in a valid JSON format with the following schema, including the leading and trailing "```json" and "```" 
                ```json
                {
                        "result": boolean,  // the result of vulnerability verification (true = the vulnerability exists, false = the vulnerability does not exist)
                        "cot" : "<the thinking process for the vulnerability verification (Step 1)>",
                        "root_cause": string // the root cause of the vulnerability of {cwe_type} wihtin [Target Code] (Step 2)
                        
                }
                ```
                """
            ) # dedent end

            # Create chain
            prompt = ChatPromptTemplate([
                    ("system",textwrap.dedent(
                            """
                            You are an expert software security engineer. Your goal is to analyse user-provided [Target Code] and verify if a vulnerability of {cwe_type} exists.
                            
                            Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                            1) Verify if {cwe_type} exists in [Target Code]
                            2) Based on the vulnerability verification thinking process from Step 1, identify the root cause of {cwe_type} wihtin [Target Code].
                            3) Provide the results {format_instructions}
                            """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                            """
                            [Supplementary Code]
                            {target_supplementary_code}

                            [Target Code]
                            {target_code}
                            """
                        ) # dedent end
                    ),
                    ("ai", textwrap.dedent( 
                        """
                        Now, I will analyse user-provided [Target Code] and verify if a vulnerability of {cwe_type} exists, and then, provide the results {format_instructions}

                        Let's think step-by-step.

                        Step 1: Verify if {cwe_type} exists in [Target Code].
                                    
                        """
                        ) # dedent end
                    )
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
            print("LLM output not directly JSON. Need manual parsing.")
            print(e)
            print(output)
            if json_output_text:
                print("=============Parsed TEXT===============")
                print(json_output_text)
            return None

        return json_output

    def invoke(self, input):
        return self.chain.invoke(input)