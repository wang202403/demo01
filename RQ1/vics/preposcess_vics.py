import os
import re
import json

def analyze_cwe_examples(directory):
    """
    Analyze files in the given directory to extract CWE examples and classify situations.

    Parameters:
        directory (str): Path to the directory containing the files.

    Returns:
        dict: A dictionary with CWE types as keys and extracted example data as values.
    """
    # Define regex pattern to match file names
    file_pattern = re.compile(r"^(CWE\d+)_.*_(.+)\.c$")
    
    # Initialize storage for results
    cwe_files = {}
    for filename in os.listdir(directory):
        match = file_pattern.match(filename)
        if match:
            cwe_id = match.group(1)
            file_type = match.group(2)  # "vul" or "nonvul"
            if cwe_id not in cwe_files:
                cwe_files[cwe_id] = {"vul": [], "nonvul": []}
            cwe_files[cwe_id][file_type].append(os.path.join(directory, filename))
    
    # Only process the top 10 most common CWE types
    sorted_cwe_ids = sorted(cwe_files.keys(), key=lambda x: len(cwe_files[x]["vul"]), reverse=True)[:10]
    cwe_examples = {}

    # Process each CWE ID in the top 10
    for cwe_id in sorted_cwe_ids:
        examples = []
        for vul_file, nonvul_file in zip(cwe_files[cwe_id]["vul"], cwe_files[cwe_id]["nonvul"]):
            with open(nonvul_file, "r") as f_nonvul, open(vul_file, "r") as f_vul:
                v1_code = restore_lines(f_nonvul.read().strip())
                v2_code = restore_lines(f_vul.read().strip())
                
                # Detect situation based on differences
                situation, v2_modified = detect_situation_with_modifications(v1_code, v2_code)
                
                # Store the example
                examples.append({
                    "situation": situation,
                    "v1": v1_code,
                    "v2": v2_modified
                })

        # Keep only the 5 simplest examples (least lines of difference in v2)
        examples = sorted(examples, key=lambda x: len(x["v2"].splitlines()))[:5]
        cwe_examples[cwe_id] = examples
    
    return cwe_examples

def restore_lines(code):
    """
    Restore proper line formatting for a code block that may have had all its lines removed.

    Parameters:
        code (str): The original code block.

    Returns:
        str: The code with lines restored.
    """
    return "\n".join(line.strip() for line in code.split(";") if line.strip()) + "\n"

def detect_situation_with_modifications(v1_code, v2_code):
    """
    Detect the situation type and modify v2 to only include the differences.

    Parameters:
        v1_code (str): Code from the fixed version.
        v2_code (str): Code from the vulnerable version.

    Returns:
        tuple: Situation type (1 to 7) and a modified v2 with only differences.
    """
    v1_lines = v1_code.splitlines()
    v2_lines = v2_code.splitlines()
    v1_set = set(v1_lines)
    v2_set = set(v2_lines)
    
    removed = v1_set - v2_set
    added = v2_set - v1_set
    modified_v2 = []

    # Analyze differences
    if removed and not added:
        situation = 1  # Removal
        for line in removed:
            modified_v2.append(f"// Removed: '{line}' from line {v1_lines.index(line) + 1}")
    elif added and not removed:
        situation = 2  # Addition
        for line in added:
            modified_v2.append(f"// Added at line {v2_lines.index(line) + 1}: {line}")
    elif removed and added:
        situation = 3  # Modification
        for line in removed:
            modified_v2.append(f"// Modified: '{line}' removed from line {v1_lines.index(line) + 1}")
        for line in added:
            modified_v2.append(f"// Modified: '{line}' added at line {v2_lines.index(line) + 1}")
    elif removed and added:
        situation = 5  # Removal + Addition
        for line in removed:
            modified_v2.append(f"// Removed: '{line}' from line {v1_lines.index(line) + 1}")
        for line in added:
            modified_v2.append(f"// Added at line {v2_lines.index(line) + 1}: {line}")
    elif added and removed:
        situation = 6  # Modification + Addition
        for line in removed:
            modified_v2.append(f"// Modified: '{line}' removed from line {v1_lines.index(line) + 1}")
        for line in added:
            modified_v2.append(f"// Added at line {v2_lines.index(line) + 1}: {line}")
    else:
        situation = 0  # Unknown situation

    return situation, "\n".join(modified_v2)

def save_to_json(data, output_file):
    """
    Save the extracted data to a JSON file.

    Parameters:
        data (dict): The extracted CWE examples.
        output_file (str): Path to the output JSON file.
    """
    with open(output_file, "w") as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    # Example usage
    directory = "SARD"  # Replace with your directory path
    output_file = "SARD_COT.json"
    
    # Analyze the files and extract examples
    results = analyze_cwe_examples(directory)
    
    # Save the results to a JSON file
    save_to_json(results, output_file)
