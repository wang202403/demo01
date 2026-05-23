import os
import json

# CASE STUDIES: STEP 3.

LLM = "GPT-4o"
DATASET = "CVE-LLM"
script_dir = os.path.dirname(__file__)

# Open the .json file corresponding to the Case Study data for the LLM and dataset.
case_study_path = os.path.join(script_dir, "case_studies", f"{LLM}_{DATASET}_case_study.json")
with open(case_study_path, 'r') as input_file:
    data = input_file.read()
case_study = json.loads(data)

# Initialize a dictionary to store Case Study data.
data_dict = {
    "Single-line": 0,
    "Multi-line": 0,
    "Insertion": 0,
    "Deletion": 0,
    "Modification": 0,
    "Partial_Response": 0,
    "Refusal": 0
}

for file, list in case_study.items():
    data = tuple(list)
    
    if LLM == "GPT-4o" and DATASET == "SARD":
        if file.endswith("_vul.c"):
            continue

    # If the data was a partial response, increment the Partial_Response count and do not continue with the analysis.
    if data[2] == "True":
        data_dict["Partial_Response"] = data_dict["Partial_Response"] + 1
    
    # If the LLM refused to provide a useful response.
    elif data[0] == "False" and data[1] == "False" and data[2] == "False":
        data_dict["Refusal"] = data_dict["Refusal"] + 1

    # Otherwise, increment the appropriate counts based on the data.
    else:
        if data[0] == "single":
            data_dict["Single-line"] = data_dict["Single-line"] + 1
        elif data[0] == "multi":
            data_dict["Multi-line"] = data_dict["Multi-line"] + 1
        
        if data[1] == "insertion":
            data_dict["Insertion"] = data_dict["Insertion"] + 1
        elif data[1] == "deletion":
            data_dict["Deletion"] = data_dict["Deletion"] + 1
        elif data[1] == "modification":
            data_dict["Modification"] = data_dict["Modification"] + 1

print(data_dict)