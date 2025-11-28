from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI,OpenAI
import textwrap
import json
import re
import sys

class AutoPatchTaintVariableAnalyzer:
    
    def __init__(self, model):

        self.model =model

        if isinstance(self.model, ChatOpenAI):
            # Create Parser
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
                    ("system", textwrap.dedent(
                        """
                        You are an expert software engineer. Your goal is to perform taint-analysis on each of the variables referenced by the user-provided [Target Code] and provide entirely self-contained explanations of the variables' functionalities in [Target Code]. Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                        1) Extract all the referenced variables within [Target Code].
                        - At least the variables in [Data Flow] MUST be extracted.
                        2) For each extracted variable, trace its **data flow** within [Target Code].  
                        - Use the [Data Flow] (format: "source variable/function" => destination variable/function list) to track how the variable is initialized, transformed, passed to functions, or conditionally manipulated.  
                        3) For each variable, generate a **low-level, self-contained explanation** of its functionality.  
                        - The explanation MUST include:  
                            - The origin of the variable (input, derived from another variable, returned from a function, etc.).  
                            - The operations performed on it (arithmetic, logical checks, memory management, iteration, dereferencing, etc.).  
                            - How it interacts with other variables or functions (dependencies, propagation, transformations).  
                            - The final role or outcome (what state it contributes to, what it enables, what risk it introduces).  
                        - The explanation MUST NOT reference specific variable/function names. Instead, describe their roles in **abstract technical terms** (e.g., “a memory buffer holding intermediate graphical state,” “a counter that governs iteration termination”).  
                        - Each explanation MUST be **self-contained** so it can be understood in isolation, without looking at [Target Code].  
                        4) Finally, provide the self-contained variable functionality explanations {format_instructions}
                        """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                        """
                        [Supplementary Code]
                        None

                        [Target Code]
                        ```c
                        int binary_search(int arr[], int size, int target) {{
                            int left = 0;
                            int right = size - 1;
                            
                            while (left <= right) {{
                                int mid = left + (right - left) / 2;
                                
                                if (arr[mid] == target)
                                    return mid;
                                else if (arr[mid] < target)
                                    left = mid + 1;
                                else
                                    right = mid - 1;
                            }}
                            
                            return -1;
                        }} // End of Implementation
                        ```

                        [Data Flow]
                        {{'left': ['right', 'mid'], 'right': ['left', 'mid'], 'mid': ['left', 'right'], 'size': ['left', 'right', 'mid']}}
                        
                        """) # dedent end   
                    ),
                    ("ai", textwrap.dedent(
                        """
                        Now, I will perform taint-analysis on each of the variables referenced by the user-provided [Target Code], and then, provide the self-contained variable functionality explanations {format_instructions}

                        Let's think step-by-step.

                        Step 1: Extract all the referenced variables within [Target Code].
                        From the function "int binary_search(int arr[], int size, int target)", we can extract the following variables:
                        - arr (function parameter)
                        - size (function parameter)
                        - target (function parameter)
                        - left (local variable)
                        - right (local variable)
                        - mid (local variable)

                        Step 2: Analyze the data flow within [Target Code].
                        - arr: Used in arr[mid] to compare elements with target. The values inside arr[] are never modified; only read.
                        - size: Used once in right = size - 1 to determine the initial bounds of the search. Provides the array's length, which influences loop limits.
                        - target: Used in comparisons against arr[mid]. Never modified; only read.
                        - left: Initialized to 0. Updated in the loop when arr[mid] < target with left = mid + 1. Part of loop condition: while (left <= right).
                        - right: Initialized to size - 1. Updated in the loop when arr[mid] > target with right = mid - 1. Part of loop condition: while (left <= right).
                        - mid: Calculated as left + (right - left) / 2 on each iteration. Used to index into arr[mid].

                        Step 3: For each variable, explain its main functionality in a low-level, self-contained way.
                        - arr: A read-only sequence of elements being examined during the search.
                        - size: A fixed numeric limit defining the number of elements to be processed.
                        - target: A constant value used as the reference for comparison in each iteration.
                        - left: A mutable boundary representing the lower limit of the current search range, adjusted upward when the middle element is less than the reference value.
                        - right: A mutable boundary representing the upper limit of the current search range, adjusted downward when the middle element is greater than the reference value.
                        - mid: A dynamically computed position representing the midpoint between the current lower and upper bounds, used to access and compare an element in the sequence.
                        
                        Step 4: Provide the self-contained variable functionality explanations in JSON format.
                        ```json
                        {{
                        "arr": "A read-only sequence of elements being examined during the search.",
                        "size": "A fixed numeric limit defining the number of elements to be processed.",
                        "target": "A constant value used as the reference for comparison in each iteration.",
                        "left": "A mutable boundary representing the lower limit of the current search range, adjusted upward when the middle element is less than the reference value.",
                        "right": "A mutable boundary representing the upper limit of the current search range, adjusted downward when the middle element is greater than the reference value.",
                        "mid": "A dynamically computed position representing the midpoint between the current lower and upper bounds, used to access and compare an element in the sequence."
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

                        [Data Flow]
                        {data_flow}
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
                    ("system", textwrap.dedent(
                        """
                        You are an expert software engineer. Your goal is to perform taint-analysis on each of the variables referenced by the user-provided [Target Code] and provide entirely self-contained explanations of the variables' functionalities in [Target Code]. Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                        1) Extract all the referenced variables within [Target Code].
                        - At least the variables in [Data Flow] MUST be extracted.
                        2) For each extracted variable, trace its **data flow** within [Target Code].  
                        - Use the [Data Flow] (format: "source variable/function" => destination variable/function list) to track how the variable is initialized, transformed, passed to functions, or conditionally manipulated.  
                        3) For each variable, generate a **low-level, self-contained explanation** of its functionality.  
                        - The explanation MUST include:  
                            - The origin of the variable (input, derived from another variable, returned from a function, etc.).  
                            - The operations performed on it (arithmetic, logical checks, memory management, iteration, dereferencing, etc.).  
                            - How it interacts with other variables or functions (dependencies, propagation, transformations).  
                            - The final role or outcome (what state it contributes to, what it enables, what risk it introduces).  
                        - The explanation MUST NOT reference specific variable/function names. Instead, describe their roles in **abstract technical terms** (e.g., “a memory buffer holding intermediate graphical state,” “a counter that governs iteration termination”).  
                        - Each explanation MUST be **self-contained** so it can be understood in isolation, without looking at [Target Code].  
                        4) Finally, provide the self-contained variable functionality explanations {format_instructions}
                        """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                        """
                        [Supplementary Code]
                        None

                        [Target Code]
                        ```c
                        int binary_search(int arr[], int size, int target) {{
                            int left = 0;
                            int right = size - 1;
                            
                            while (left <= right) {{
                                int mid = left + (right - left) / 2;
                                
                                if (arr[mid] == target)
                                    return mid;
                                else if (arr[mid] < target)
                                    left = mid + 1;
                                else
                                    right = mid - 1;
                            }}
                            
                            return -1;
                        }} // End of Implementation
                        ```

                        [Data Flow]
                        {{'left': ['right', 'mid'], 'right': ['left', 'mid'], 'mid': ['left', 'right'], 'size': ['left', 'right', 'mid']}}
                        
                        """) # dedent end   
                    ),
                    ("ai", textwrap.dedent(
                        """
                        Now, I will perform taint-analysis on each of the variables referenced by the user-provided [Target Code], and then, provide the self-contained variable functionality explanations {format_instructions}

                        Let's think step-by-step.

                        Step 1: Extract all the referenced variables within [Target Code].
                        From the function "int binary_search(int arr[], int size, int target)", we can extract the following variables:
                        - arr (function parameter)
                        - size (function parameter)
                        - target (function parameter)
                        - left (local variable)
                        - right (local variable)
                        - mid (local variable)

                        Step 2: Analyze the data flow within [Target Code].
                        - arr: Used in arr[mid] to compare elements with target. The values inside arr[] are never modified; only read.
                        - size: Used once in right = size - 1 to determine the initial bounds of the search. Provides the array's length, which influences loop limits.
                        - target: Used in comparisons against arr[mid]. Never modified; only read.
                        - left: Initialized to 0. Updated in the loop when arr[mid] < target with left = mid + 1. Part of loop condition: while (left <= right).
                        - right: Initialized to size - 1. Updated in the loop when arr[mid] > target with right = mid - 1. Part of loop condition: while (left <= right).
                        - mid: Calculated as left + (right - left) / 2 on each iteration. Used to index into arr[mid].

                        Step 3: For each variable, explain its main functionality in a low-level, self-contained way.
                        - arr: A read-only sequence of elements being examined during the search.
                        - size: A fixed numeric limit defining the number of elements to be processed.
                        - target: A constant value used as the reference for comparison in each iteration.
                        - left: A mutable boundary representing the lower limit of the current search range, adjusted upward when the middle element is less than the reference value.
                        - right: A mutable boundary representing the upper limit of the current search range, adjusted downward when the middle element is greater than the reference value.
                        - mid: A dynamically computed position representing the midpoint between the current lower and upper bounds, used to access and compare an element in the sequence.
                        
                        Step 4: Provide the self-contained variable functionality explanations in JSON format.
                        ```json
                        {{
                        "arr": "A read-only sequence of elements being examined during the search.",
                        "size": "A fixed numeric limit defining the number of elements to be processed.",
                        "target": "A constant value used as the reference for comparison in each iteration.",
                        "left": "A mutable boundary representing the lower limit of the current search range, adjusted upward when the middle element is less than the reference value.",
                        "right": "A mutable boundary representing the upper limit of the current search range, adjusted downward when the middle element is greater than the reference value.",
                        "mid": "A dynamically computed position representing the midpoint between the current lower and upper bounds, used to access and compare an element in the sequence."
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
                        
                        [Data Flow]
                        {data_flow}
                        
                        """
                        ) # dedent end
                    ),
                    ("ai", textwrap.dedent( 
                        """
                        Now, I will perform taint-analysis on each of the variables referenced by the user-provided [Target Code], and then, provide the self-contained variable functionality explanations {format_instructions}

                        Let's think step-by-step.

                        Step 1: Extract all the referenced variables within [Target Code].
                                    
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
        json_output_text= None
        try:
            json_output_text = re.findall(r'```json\s*(\{.*?\})\s*```', output, re.DOTALL)[-1].strip()
            json_output = json.loads(json_output_text)
        except Exception as e:
            print("LLM output not directly JSON. Need manual parsing.")
            print(e)
            print("=============== output str ==================")
            print(output)
            if json_output_text:
                print("=============== matched str ==================")
                print(json_output_text)
            return None

        return json_output

    def invoke(self, input):
        return self.chain.invoke(input)