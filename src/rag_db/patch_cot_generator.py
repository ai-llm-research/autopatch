from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI
import textwrap
import json
import re

class AutoPatchDBPatchCoTGenerator:
    
    def __init__(self, model):
        # Format instructions
        format_instructions =textwrap.dedent(
            """
            in the following schema, including the leading and trailing "```json" and "```" 
            ```json
            {
                    "fix_list": string, // the fix-list to patch the snippet that is vulnerable to the same [CVE] (Step 2)
                    "cot": string // the thinking process to patch [Vulnerable Code] (Step 3)
            }
            ```
            """
        ) # dedent end

        # Create chain
        prompt = ChatPromptTemplate([
                ("system",textwrap.dedent(
                        """
                        You are an expert software security engineer. Your task is to provide the fix-list to patch vulnerabilities similar to the user-provided [CVE] that occurred in [Vulnerable Code]. Perform the following steps in order and show the reasoning in each step. Start your answer with "Let's think step-by-step."
                        1) Given the user-provided [Root Cause] and [Patched Code] of [CVE], analyze how the patched lines in [Patched Code] fixes [CVE].
                        2) Given that a user can match each of [Vulnerability-Related Variables] and [Vulnerability-Related Functions] to a counterpart in their own code snippet, which is vulnerable to the same [CVE], provide the fix-list to patch the snippet.
                            - Important: Present each fix-list item in terms of [Vulnerability-Related Variables] and [Vulnerability-Related Functions] (e.g., “Check if function <function_name> is safely handling variable <variable_name>” or “Verify that variable <variable_name> is properly sanitized before it is passed to function <function_name>”).
                        3) Using the fix-list from Step 2, describe, step-by-step, how to patch the vulnerability similar to [CVE] that exists in the [Vulnerable Code].
                        4) Finally, provide the results {format_instructions}
                        """ 
                    ) # dedent end
                ),
                ("user", textwrap.dedent(
                        """
                        [CWE]
                        {cwe_type}

                        [Supplementary Code]
                        {supplementary_code}
                        
                        [Target Code]
                        {target_code}

                        [Vulnerability Root Cause]
                        {root_cause}

                        [Vulnerability-Related Functions]
                        {vulnerability_related_functions}

                        [Vulnerability-Related Variables]
                        {vulnerability_related_variables}
                        
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
        except Exception:
            print("LLM output not directly JSON. Need manual parsing.")
            return None
        return json_output


    def invoke(self, input):
        return self.chain.invoke(input)