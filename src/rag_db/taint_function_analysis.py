from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI
import textwrap
import json
import re

class AutoPatchDBTaintFunctionAnalyser:
    
    def __init__(self, model):
        # Format instructions
        format_instructions =textwrap.dedent(
            """
            in the following schema, including the leading and trailing "```json" and "```" 
            ```json
            {
                    "<function_1_name>": string,  // the self-contained explanation of function_1
                    "<function_2_name>": string,  // the self-contained explanation of function_2
                    ...
                    "<function_n_name>": string  // the self-contained explanation of function_n
            }
            ```
            """
        ) # dedent end

        # Create chain
        prompt = ChatPromptTemplate([
                ("system",textwrap.dedent(
                        """
                        You are an expert software engineer. Your goal is to perform taint-analysis on each of the functions referenced by the user-provided [Target Code] and provide entirely self-contained explanations of the functions' functionalities in [Target Code]. Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                        1) For each function in [Target Functions], trace its **data flow** within [Target Code].  
                        - Use the [Data Flow] (format: "source variable/function" => destination variable/function list) to track how the function is used, how its output is propagated, and how it interacts with other variables or functions.
                        - If the function is in [Supplementary Code], you can use it to understand the data flow.
                        2) For each function, generate a **low-level, self-contained explanation** of its functionality.  
                        - The explanation MUST include:  
                            - The role of the function's inputs (where they originate and how they are validated or transformed).  
                            = The internal operations (e.g., logical branching, arithmetic, memory management, data structure manipulation, iteration, synchronization).  
                            - How the function interacts with external state or other components (e.g., modifies buffers, updates counters, signals errors).  
                            - The function's final outcome (e.g., initializes a resource, validates conditions, propagates data, releases memory, introduces risks).  
                        - The explanation MUST NOT reference specific variable/function names. Instead, describe their roles in **abstract technical terms** (e.g., “a memory buffer holding intermediate graphical state,” “a counter that governs iteration termination”).  
                        - Each explanation MUST be **self-contained** so it can be understood in isolation, without looking at [Target Code].  
                        3) Finally, provide the self-contained function functionality explanations {format_instructions}
                        """ 
                    ) # dedent end
                ),
                ("user", textwrap.dedent(
                        """
                        [Supplementary Code]
                        {supplementary_code}
                        
                        [Target Code]
                        {target_code}
                        
                        [Data Flow]
                        {data_flow}

                        [Target Functions]
                        {target_functions}
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