from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain.output_parsers import ResponseSchema, StructuredOutputParser
from langchain_openai import ChatOpenAI,OpenAI
import textwrap
import json
import re
import sys

class AutoPatchTaintFunctionAnalyzer:
    
    def __init__(self, model):

        self.model =model

        if isinstance(self.model, ChatOpenAI):
            # Create Parser
            format_instructions =textwrap.dedent(
                """
                in valid JSON format with the following schema, including the leading and trailing "```json" and "```" 
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
                    ("system", textwrap.dedent(
                        """
                        You are an expert software engineer. Your goal is to perform taint-analysis on each of the functions referenced by the user-provided [Target Code] and provide entirely self-contained explanations of the functions' functionalities in [Target Code]. Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                        1) Extract all the referenced functions (including function-like macro with parentheses) within [Target Code].
                        - At least the functions in [Data Flow] MUST be extracted.
                        2) For each extracted function, trace its **data flow** within [Target Code].  
                        - Use the [Data Flow] (format: "source variable/function" => destination variable/function list) to track how the function is used, how its output is propagated, and how it interacts with other variables or functions.
                        - If the function is in [Supplementary Code], you can use it to understand the data flow.
                        3) For each function, generate a **low-level, self-contained explanation** of its functionality.  
                        - The explanation MUST include:  
                            - The role of the function's inputs (where they originate and how they are validated or transformed).  
                            = The internal operations (e.g., logical branching, arithmetic, memory management, data structure manipulation, iteration, synchronization).  
                            - How the function interacts with external state or other components (e.g., modifies buffers, updates counters, signals errors).  
                            - The function's final outcome (e.g., initializes a resource, validates conditions, propagates data, releases memory, introduces risks).  
                        - The explanation MUST NOT reference specific variable/function names. Instead, describe their roles in **abstract technical terms** (e.g., “a memory buffer holding intermediate graphical state,” “a counter that governs iteration termination”).  
                        - Each explanation MUST be **self-contained** so it can be understood in isolation, without looking at [Target Code].  
                        4) Finally, provide the self-contained function functionality explanations {format_instructions}
                        """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                        """
                        [Supplementary Code]
                        ```c
                        int calculate_sum(int arr[], int size) {{
                            int total = 0;
                            for (int i = 0; i < size; i++)
                                total += arr[i];
                            return total;
                        }}

                        int calculate_average(int total, int count) {{
                            if (count == 0)
                                return 0;
                            return total / count;
                        }}
                        ```

                        [Target Code]
                        ```c
                        int process_data(int arr[], int size) {{
                            int sum = calculate_sum(arr, size);
                            int avg = calculate_average(sum, size);

                            if (avg > 100)
                                return 1;
                            else
                                return 0;
                        }}
                        ```

                        [Data Flow]
                        {{'sum': ['avg', 'calculate_average'], 'calculate_average': ['avg'], 'calculate_sum': ['sum', 'avg', 'calculate_average'], 'arr': ['sum', 'avg', 'calculate_average', 'calculate_sum'], 'size': ['sum', 'avg', 'calculate_average', 'calculate_sum']}}
                        
                        """) # dedent end   
                    ),
                    ("ai", textwrap.dedent(
                        """
                        Now, I will perform taint-analysis on each of the variables referenced by the user-provided [Target Code], and then, provide the self-contained variable functionality explanations {format_instructions}

                        Let's think step-by-step.

                        Step 1: Extract all the referenced functions within [Target Code].
                        The [Target Code] references the following functions:
                        - calculate_sum
                        - calculate_average

                        Step 2: Analyze their data flow within [Target Code].
                        - calculate_sum: takes an array and its size and returns the total sum of its elements. The result is stored in `sum`.
                        - calculate_average: takes the previously calculated sum and the size of the array to compute the average. The result is stored in `avg`.

                        Step 3: For each function, explain its main functionality in a low-level, self-contained way.
                        - calculate_sum: An iterative procedure that computes the total value by accumulating all numeric elements from a sequence.
                        - calculate_average: A division-based computation that returns the mean of two numeric inputs by dividing the cumulative value by the count, with a guard against division by zero.

                        Step 4: Provide the self-contained variable functionality explanations in JSON format.
                        ```json
                        {{
                        "calculate_sum": "An iterative procedure that computes the total value by accumulating all numeric elements from a sequence.",
                        "calculate_average": "A division-based computation that returns the mean of two numeric inputs by dividing the cumulative value by the count, with a guard against division by zero."
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
                    ("system", textwrap.dedent(
                        """
                        You are an expert software engineer. Your goal is to perform taint-analysis on each of the functions referenced by the user-provided [Target Code] and provide entirely self-contained explanations of the functions' functionalities in [Target Code]. Perform the followings step by step and show the reasoning in each step. Start answering with "Let's think step-by-step."
                        1) Extract all the referenced functions (including function-like macro with parentheses) within [Target Code].
                        - At least the functions in [Data Flow] MUST be extracted.
                        2) For each extracted function, trace its **data flow** within [Target Code].  
                        - Use the [Data Flow] (format: "source variable/function" => destination variable/function list) to track how the function is used, how its output is propagated, and how it interacts with other variables or functions.
                        - If the function is in [Supplementary Code], you can use it to understand the data flow.
                        3) For each function, generate a **low-level, self-contained explanation** of its functionality.  
                        - The explanation MUST include:  
                            - The role of the function's inputs (where they originate and how they are validated or transformed).  
                            = The internal operations (e.g., logical branching, arithmetic, memory management, data structure manipulation, iteration, synchronization).  
                            - How the function interacts with external state or other components (e.g., modifies buffers, updates counters, signals errors).  
                            - The function's final outcome (e.g., initializes a resource, validates conditions, propagates data, releases memory, introduces risks).  
                        - The explanation MUST NOT reference specific variable/function names. Instead, describe their roles in **abstract technical terms** (e.g., “a memory buffer holding intermediate graphical state,” “a counter that governs iteration termination”).  
                        - Each explanation MUST be **self-contained** so it can be understood in isolation, without looking at [Target Code].  
                        4) Finally, provide the self-contained function functionality explanations {format_instructions}
                        """
                        ) # dedent end
                    ),
                    ("user", textwrap.dedent(
                        """
                        [Supplementary Code]
                        ```c
                        int calculate_sum(int arr[], int size) {{
                            int total = 0;
                            for (int i = 0; i < size; i++)
                                total += arr[i];
                            return total;
                        }}

                        int calculate_average(int total, int count) {{
                            if (count == 0)
                                return 0;
                            return total / count;
                        }}
                        ```

                        [Target Code]
                        ```c
                        int process_data(int arr[], int size) {{
                            int sum = calculate_sum(arr, size);
                            int avg = calculate_average(sum, size);

                            if (avg > 100)
                                return 1;
                            else
                                return 0;
                        }}
                        ```
                        
                        [Data Flow]
                        {{'sum': ['avg', 'calculate_average'], 'calculate_average': ['avg'], 'calculate_sum': ['sum', 'avg', 'calculate_average'], 'arr': ['sum', 'avg', 'calculate_average', 'calculate_sum'], 'size': ['sum', 'avg', 'calculate_average', 'calculate_sum']}}
                        
                        """) # dedent end   
                    ),
                    ("ai", textwrap.dedent(
                        """
                        Now, I will perform taint-analysis on each of the variables referenced by the user-provided [Target Code], and then, provide the self-contained variable functionality explanations {format_instructions}

                        Let's think step-by-step.

                        Step 1: Extract all the referenced functions within [Target Code].
                        The [Target Code] references the following functions:
                        - calculate_sum
                        - calculate_average

                        Step 2: Analyze their data flow within [Target Code].
                        - calculate_sum: takes an array and its size and returns the total sum of its elements. The result is stored in `sum`.
                        - calculate_average: takes the previously calculated sum and the size of the array to compute the average. The result is stored in `avg`.

                        Step 3: For each function, explain its main functionality in a low-level, self-contained way.
                        - calculate_sum: An iterative procedure that computes the total value by accumulating all numeric elements from a sequence.
                        - calculate_average: A division-based computation that returns the mean of two numeric inputs by dividing the cumulative value by the count, with a guard against division by zero.

                        Step 4: Provide the self-contained variable functionality explanations in JSON format.
                        ```json
                        {{
                        "calculate_sum": "An iterative procedure that computes the total value by accumulating all numeric elements from a sequence.",
                        "calculate_average": "A division-based computation that returns the mean of two numeric inputs by dividing the cumulative value by the count, with a guard against division by zero."
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

                        Step 1: Extract all the referenced functions within [Target Code].
                                    
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
            json_output_text = re.findall(r'```json\s*(\{.*?\})\s*```', output, re.DOTALL)[-1].strip()
            json_output = json.loads(json_output_text)
        except Exception:
            print("LLM output not directly JSON. Need manual parsing.")
            print(output)
            return None

        return json_output

    def invoke(self, input):
        return self.chain.invoke(input)