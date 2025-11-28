from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI
import textwrap
import json
import re

class AutoPatchDBTaintVariableAnalyser:
    
    def __init__(self, model):
        # Format instructions
        format_instructions =textwrap.dedent(
            """
            in valid JSON format with the following schema, including the leading and trailing "```json" and "```" 
            ```json
            {
                    "<variable_1_name>": string,  // the self-contained explanation of variable_1
                    "<variable_2_name>": string,  // the self-contained explanation of variable_2
                    ...
                    "<variable_n_name>": string  // the self-contained explanation of variable_n
            }
            ```
            """
        ) # dedent end

        # Create chain
        prompt = ChatPromptTemplate([
                ("system",textwrap.dedent(
                        """
                        You are an expert software engineer. Your goal is to perform taint-analysis on each of the variables in [Target Variables] and provide entirely self-contained explanations of the variables' functionalities in [Target Code]. Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step.
                        1) For each variable in [Target Variables], trace its **data flow** within [Target Code].  
                        - Use the [Data Flow] (format: "source variable/function" => destination variable/function list) to track how the variable is initialized, transformed, passed to functions, or conditionally manipulated.  
                        2) For each variable, generate a **low-level, self-contained explanation** of its functionality.  
                        - The explanation MUST include:  
                            - The origin of the variable (input, derived from another variable, returned from a function, etc.).  
                            - The operations performed on it (arithmetic, logical checks, memory management, iteration, dereferencing, etc.).  
                            - How it interacts with other variables or functions (dependencies, propagation, transformations).  
                            - The final role or outcome (what state it contributes to, what it enables, what risk it introduces).  
                        - The explanation MUST NOT reference specific variable/function names. Instead, describe their roles in **abstract technical terms** (e.g., “a memory buffer holding intermediate graphical state,” “a counter that governs iteration termination”).  
                        - Each explanation MUST be **self-contained** so it can be understood in isolation, without looking at [Target Code].  
                        3) Finally, provide the self-contained variable functionality explanations {format_instructions}
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
                        
                        [Target Variables]
                        {target_variables} 
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