from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI, OpenAI
import textwrap
import json
import re
import sys

class AutoPatchBaselinePatcher:
    
    def __init__(self, model):

        self.model =model

        if isinstance(self.model, ChatOpenAI):
            # Format instructions
            format_instructions =textwrap.dedent(
                """
                in the following format, including the leading and trailing "```" and "```" 
                ```
                [CoT START]
                <the thinking process for the vulnerability patching (Step 1)>
                [CoT END]

                [Patched Code START]
                <the patched code>
                [Patched Code END]
                ```
                """
            ) # dedent end

            # Create chain
            prompt = ChatPromptTemplate([
                    ("system",textwrap.dedent(
                            """
                            You are an expert software security engineer. Your goal is to patch user-provided [Target Code] having a vulnerabilitiy of {cwe_type}.                  

                            Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                            1) Think of the way to patch {cwe_type} that is caused due to [Root Cause].
                            2) Use the patch description from Step 1 to generate a patched code.
                            3) Provide the results {format_instructions}
                            """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                            """
                            [Supplementary Code]
                            {target_supplementary_code}

                            [Root Cause]
                            {target_root_cause}

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
                in the following format, including the leading and trailing "```" and "```" 
                ```
                [CoT START]
                <the thinking process for the vulnerability patching (Step 1)>
                [CoT END]

                [Patched Code START]
                <the patched code>
                [Patched Code END]
                ```
                """
            ) # dedent end

            # Create chain
            prompt = ChatPromptTemplate([
                    ("system",textwrap.dedent(
                            """
                            You are an expert software security engineer. Your goal is to patch user-provided [Target Code] having a vulnerabilitiy of {cwe_type}.                  

                            Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                            1) Describe how to patch [Target Code] to fix {cwe_type} that is caused due to [Root Cause].
                            2) Use the patch description from Step 1 to generate a patched code.
                            3) Provide the results {format_instructions}
                            """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                            """
                            [Supplementary Code]
                            {target_supplementary_code}

                            [Root Cause]
                            {target_root_cause}

                            [Target Code]
                            {target_code}
                            """
                        ) # dedent end
                    ),
                    ("ai", textwrap.dedent( 
                        """
                        Now, I will patch user-provided [Target Code] having a vulnerabilitiy of {cwe_type}, and then, provide the results {format_instructions}

                        Let's think step-by-step.

                        Step 1: Describe how to patch [Target Code] to fix {cwe_type} that is caused due to [Root Cause].
                         
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
        try:
            cot = output[output.find('[CoT START]') + len('[CoT START]'): output.find('[CoT END]')]
            vuln_patch = output[output.find('[Patched Code START]') + len('[Patched Code START]'): output.find('[Patched Code END]')]
            json_output = {"cot": cot, "vuln_patch":vuln_patch}
        except Exception as e:
            print("LLM output not directly JSON2. Need manual parsing.")
            print(output)
            return None

        return json_output

    def invoke(self, input):
        return self.chain.invoke(input)