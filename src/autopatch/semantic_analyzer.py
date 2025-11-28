from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI,OpenAI
import textwrap
import json
import re
import sys

class AutoPatchSemanticAnalyzer:
    
    def __init__(self, model):

        self.model = model

        if isinstance(self.model, ChatOpenAI):
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
                    ("user", textwrap.dedent(
                        """
                        [Supplementary Code]
                        ```c
                        int double_if_odd(int x) {{
                            if (x % 2 != 0)
                                return x * 2;
                            else
                                return x;
                        }}
                        ```

                        [Target Code]
                        ```c
                        int process_array(int arr[], int size) {{
                            int result = 0;
                            for (int i = 0; i < size; i++) {{
                                result += double_if_odd(arr[i]);
                            }}
                            return result;
                        }}
                        ```
                        """
                        ) # dedent end
                    ),
                    ("ai", textwrap.dedent(
                        """
                        Now, I will analyze the function in [Target Code] and provide a self-contained summary of its functionality, and then, provide in a valid JSON format with the following schema, INCLUDING the leading and trailing BACKTICKS "```json" and "```"
                        ```json
                        {{
                                "result": string  // the self-containted explanation of [Target Code] (Step 2)
                        }}
                        ``` //FINAL RESULT

                        Let's think step-by-step.

                        Step 1: Analyze the main functionality of [Target Code].
                        - The function iterates through the array.
                        - For each element, it applies double_if_odd() and accumulates the result.
                        - Finally, it returns the sum of all processed elements.

                        Step 2: Explain the main functionality of [Target Code] in a self-contained low-level representation. The explanation must be general that it must not include external references.
                        - Iterate through a list of numbers.
                        - For each number, check if it is odd. If it is, double it; otherwise, leave it as is.
                        - Sum all the processed numbers and return the final total.

                        Step 3: Final result in JSON format.
                        ```json
                        {{
                            "result": "Iterate through a list of numbers. For each number, check if it is odd. If it is, double it; otherwise, leave it as is. Sum all the processed numbers and return the final total."
                        }}
                        ``` //FINAL RESULT
                        """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                        """
                        [Supplementary Code]
                        {supplementary_code}
                        
                        [Target Code]
                        {target_code}
                        """
                        ) # dedent end
                    )
                    ],
                    partial_variables={"format_instructions":format_instructions}
                )            
        elif isinstance(self.model, OpenAI):
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
                    ("user", textwrap.dedent(
                        """
                        [Supplementary Code]
                        ```c
                        int double_if_odd(int x) {{
                            if (x % 2 != 0)
                                return x * 2;
                            else
                                return x;
                        }}
                        ```

                        [Target Code]
                        ```c
                        int process_array(int arr[], int size) {{
                            int result = 0;
                            for (int i = 0; i < size; i++) {{
                                result += double_if_odd(arr[i]);
                            }}
                            return result;
                        }}
                        ```
                        """
                        ) # dedent end
                    ),
                    ("ai", textwrap.dedent(
                        """
                        Now, I will analyze the function in [Target Code] and provide a self-contained summary of its functionality, and then, provide in a valid JSON format with the following schema, INCLUDING the leading and trailing BACKTICKS "```json" and "```"
                        ```json
                        {{
                                "result": string  // the self-containted explanation of [Target Code] (Step 2)
                        }}
                        ``` //FINAL RESULT

                        Let's think step-by-step.

                        Step 1: Analyze the main functionality of [Target Code].
                        - The function iterates through the array.
                        - For each element, it applies double_if_odd() and accumulates the result.
                        - Finally, it returns the sum of all processed elements.

                        Step 2: Explain the main functionality of [Target Code] in a self-contained low-level representation. The explanation must be general that it must not include external references.
                        - Iterate through a list of numbers.
                        - For each number, check if it is odd. If it is, double it; otherwise, leave it as is.
                        - Sum all the processed numbers and return the final total.

                        Step 3: Final result in JSON format.
                        ```json
                        {{
                            "result": "Iterate through a list of numbers. For each number, check if it is odd. If it is, double it; otherwise, leave it as is. Sum all the processed numbers and return the final total."
                        }}
                        ``` //FINAL RESULT
                        """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                        """
                        [Supplementary Code]
                        {supplementary_code}
                        
                        [Target Code]
                        {target_code}
                        """
                        ) # dedent end
                    ),
                    ("ai", textwrap.dedent(
                        """
                        Now, I will analyze the function in [Target Code] and provide a self-contained summary of its functionality, and then, provide in a valid JSON format with the following schema, INCLUDING the leading and trailing BACKTICKS "```json" and "```"
                        ```json
                        {{
                                "result": string  // the self-containted explanation of [Target Code] (Step 2)
                        }}
                        ``` //FINAL RESULT

                        Let's think step-by-step.

                        Step 1: Analyze the main functionality of [Target Code].

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
        try:
            json_output_text = re.findall(r'```json\s*(\{.*?\})\s*```', output, re.DOTALL)[-1].strip()
            json_output = json.loads(json_output_text)
        except Exception:
            print("LLM output not directly JSON. Need manual parsing.")
            print(output)
            return None

        return json_output

    def invoke(self, input):
        return self.chain.invoke(input)