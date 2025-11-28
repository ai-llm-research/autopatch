from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI
import textwrap
import json
import re

class AutoPatchDBVerificaitonCoTGenerator:
    
    def __init__(self, model):
        # Format instructions
        format_instructions =textwrap.dedent(
            """
            in the following schema, including the leading and trailing "```json" and "```" 
            ```json
            {
                    "root_cause": string, // the root cause of the vulnerability of [CWE] wihtin [Target Code] (Step 1)
                    "vulnerability_related_variables": array,  // the list of vulnerability-related variables (Step 2)
                    "vulnerability_related_functions": array  // the list of vulnerability-related functions (Step 2)
                    "vulnerability_checklist": string, // the checklist to identify the vulnerabilities similar to [CVE] (Step 3)
                    "cot": string, // the checklist checking process to determine why [Vulnerable Code] is vulnerable to [CVE] (Step 4)
                    "safe_cot": string, // the checklist checking process to determine why [Patched Code] is not vulnerable to [CVE] (Step 5)
            }
            ```
            """
        ) # dedent end

        # Create chain
        prompt = ChatPromptTemplate([
                ("system",textwrap.dedent(
                        """
                        You are an expert software security engineer. Your task is to provide the checklist to identify vulnerabilities similar to the user-provided [CVE] that occurred in [Vulnerable Code]. Perform the following steps in order and show the reasoning in each step. Start your answer with "Let's think step-by-step."
                        1) Identify the patched lines of [CVE] by comparing [Vulnerable Code] and [Patched Code]. Then, determine the root cause of [CVE].
                        2) Based on the root cause from Step 1, identify the variables and functions that are crucial for analyzing [CVE]. These variables/functions are the key vulnerability-related elements needed for the analysis.
                        3) Given that a user can match each identified variable and function from Step 2 to a counterpart in their own code snippet, provide the checklist to verify whether the snippet is vulnerable to the same [CVE].
                            - Important: Present each checklist item in terms of the identified vulnerability-related variables and functions from Step 2 (e.g., “Check if function <function_name> is safely handling variable <variable_name>” or “Verify that variable <variable_name> is properly sanitized before it is passed to function <function_name>”).
                        4) Using the checklist from Step 3, describe, step-by-step, why the vulnerability similar to [CVE] exists in the [Vulnerable Code].
                        5) Using the same checklist from Step 3, describe, step-by-step, why the vulnerability similar to [CVE] doesn't exist in the [Patched Code].
                        6) Finally, provide the results {format_instructions}
                        """ 
                    ) # dedent end
                ),
                ("user", textwrap.dedent(
                        """
                        [CVE]
                        {cve_id}

                        [CWE]
                        {cwe_type}

                        [Supplementary Code]
                        {supplementary_code}
                        
                        [Target Code]
                        {target_code}
                        
                        [Patched Code]
                        {vuln_patch}
                        """
                        ) # dedent end
                    )
                ],
                partial_variables = {"format_instructions": format_instructions}
            )

        self.chain = prompt | model | StrOutputParser()


    def parse(self, output):
        # Now parse using JSON (or regex)
        json_output = None
        try:
            json_output_text = re.findall(r'```json\s*(\{.*?\})\s*```', output, re.DOTALL)[-1].strip()
            json_output = json.loads(json_output_text)

            if "Patched" in json_output["safe_cot"]:
                json_output["safe_cot"] = json_output["safe_cot"].replace("Patched", "Target")

        except Exception:
            print("LLM output not directly JSON. Need manual parsing.")
            return None
        return json_output


    def invoke(self, input):
        return self.chain.invoke(input)