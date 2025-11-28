from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI
import textwrap
import json
import re

class AutoPatchDBSemanticAnalyzer:
    
    def __init__(self, model):
        # Create Parser
        format_instructions =textwrap.dedent(
            """
            in the following schema, including the leading and trailing "```json" and "```" 
            ```json
            {
                    "result": string // the self-contained explanation of [Target Code] (Step 2)
            }
            ```
            """
        ) # dedent end

        # Create chain
        prompt = ChatPromptTemplate([
                ("system", textwrap.dedent(
                    """
                    You are an expert software engineer without any software security knowledge. Your goal is to analyze [Target Code] and provide a self-contained summary of its functionality. Perform the followings step by step and show the reasoning in each step. You are not aware of software security information so DO NOT deduce any security implication on any step. Start answering with "Let's think step-by-step."
                    1) Analyze the main functionality of [Target Code].
                    2) Explain the main functionality of [Target Code] in a self-contained low-level representation. The explanation must be general that it must not include any variable or function names.
                    3) Finally, provide the seld-contained explanation of [Target Code] {format_instructions}
                    """
                    ) # dedent end
                 ),
                ("user", "[Supplementary Code]\n{supplementary_code}\n\n[Target Code]\n{target_code}")
                ],
                partial_variables={"format_instructions":format_instructions}
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
