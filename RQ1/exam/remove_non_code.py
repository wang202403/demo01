import os

# STEP 3.

# >>>>> Open each file in results_unprocessed and remove everything that isn't code. <<<<<

# Combine file path of script and relative file path of dataset for absolute file path of results_unprocessed folder.
script_dir = os.path.dirname(__file__)
llm = "GPT-4o"
dataset = "CVE-LLM"
input_path = os.path.join(script_dir, llm, dataset, "results_unprocessed")
input_files = os.listdir(input_path)
output_path = os.path.join(script_dir, llm, dataset, "results_processed")

# Find the appropriate delimiters for each file or report that we could not find them.
arrow_counter = 0
def find_delimiters(input_file_path):
    global start_delim
    global end_delim
    global arrow_counter
    fail_counter = 0

    with open(input_file_path, 'r') as input_file:
        for line in input_file:
            if "```c" in line:
                start_delim = "```c"
                end_delim = "```"
                return
            elif "<" in line:
                start_delim = "<"
                end_delim = ">"
                arrow_counter += 1
                return
        fail_counter += 1
        print(f"Fail Counter = {fail_counter}, File Name: {input_file_path}")
        return -1

# Remove non-code lines from the file.
def process_c_file(input_file_path, output_file_path):
    
    # Identify the delimiters for the code in the file, if possible.
    global start_delim
    global end_delim
    global arrow_counter
    if find_delimiters(input_file_path) == -1:
        print("\nDELIMITERS NOT FOUND.\n")
        return
    
    # Transfer lines that are identified as code into the output file.
    try:
        if not input_file_path.endswith("_vul.c"):
            with open(input_file_path, 'r') as input_file:
                with open(output_file_path, 'w') as output_file:
                    
                    inside_delimiters = False  # Flag to keep track of whether we're inside the delimiters
                    complete = False # Flag to keep track of if we already transcribed some code to the output file

                    for line in input_file:
                        # Look for the start delimiter.
                        if start_delim in line:
                            inside_delimiters = True
                            continue  # Skip this line and continue to the next one

                        # Look for the end delimiter.
                        if end_delim in line:
                            inside_delimiters = False
                            complete = True
                            continue  # Skip this line and continue to the next one

                        # If we're inside the delimiters, write the line to the output file
                        if inside_delimiters and complete == False:
                            output_file.write(line)

        print(f"Processed '{input_file_path}' and saved the result to '{output_file_path}' successfully.")
    except Exception as e:
        print(f"Error processing file: {str(e)}")

# For each file in the results_unprocessed folder:
for file in input_files:
    input_file_path = os.path.join(input_path, file)
    output_file_path = os.path.join(output_path, file)
    process_c_file(input_file_path, output_file_path)

print(f"Arrow Delimiter File Count: {arrow_counter}")