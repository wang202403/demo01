import os
import json

# CASE STUDIES: STEP 3.

LLM = "LLaMa"
DATASET = "SARD"
script_dir = os.path.dirname(__file__)

# Open the .json file corresponding to the Case Study data for the LLM and dataset.
case_study_path = os.path.join(script_dir, "case_studies", f"{LLM}_{DATASET}_case_study.json")
with open(case_study_path, 'r') as input_file:
    data = input_file.read()
case_study = json.loads(data)

# Open the .json file corresponding to the manual evaluation data for the LLM and dataset.
manual_eval_path = os.path.join(script_dir, "manual_eval", f"{LLM}_{DATASET}_manual_eval.json")
with open(manual_eval_path, 'r') as input_file:
    data = input_file.read()
manual_eval = json.loads(data)

data_dict = {}
freq_dict = {
    "Partial_Response": 0,
    "Refusal": 0,
    "Single-line/Insertion/SUCCESS": 0,
    "Single-line/Insertion/FAILURE": 0,
    "Single-line/Deletion/SUCCESS": 0,
    "Single-line/Deletion/FAILURE": 0,
    "Single-line/Modification/SUCCESS": 0,
    "Single-line/Modification/FAILURE": 0,
    "Multi-line/Insertion/SUCCESS": 0,
    "Multi-line/Insertion/FAILURE": 0,
    "Multi-line/Deletion/SUCCESS": 0,
    "Multi-line/Deletion/FAILURE": 0,
    "Multi-line/Modification/SUCCESS": 0,
    "Multi-line/Modification/FAILURE": 0
}
for file_name, eval_list in manual_eval.items():

    if LLM == "GPT-4o" and DATASET == "SARD":
        if file_name.endswith("_vul.c"):
            continue

    try:
        data = case_study[file_name] + eval_list
    except Exception as e:
        print(f"Error: {e}")
        continue
    data = tuple(data)
    data_dict[file_name] = data

    # If the data was a partial response, increment the Partial_Response count and do not continue with the analysis.
    if data[2] == "True":
        freq_dict["Partial_Response"] = freq_dict["Partial_Response"] + 1
        continue
    # If the data was a refusal, increment the refusal count and do not continue with the analysis.
    elif data[0] == "False" and data[1] == "False" and data[2] == "False":
        freq_dict["Refusal"] = freq_dict["Refusal"] + 1
        continue

    if data[0] == "single" and data[1] == "insertion":
        if data[3] == True and data[4] == True and data[5] == True:
            freq_dict["Single-line/Insertion/SUCCESS"] = freq_dict["Single-line/Insertion/SUCCESS"] + 1
        else:
            freq_dict["Single-line/Insertion/FAILURE"] = freq_dict["Single-line/Insertion/FAILURE"] + 1

    if data[0] == "single" and data[1] == "deletion":
        if data[3] == True and data[4] == True and data[5] == True:
            freq_dict["Single-line/Deletion/SUCCESS"] = freq_dict["Single-line/Deletion/SUCCESS"] + 1
        else:
            freq_dict["Single-line/Deletion/FAILURE"] = freq_dict["Single-line/Deletion/FAILURE"] + 1
    
    if data[0] == "single" and data[1] == "modification":
        if data[3] == True and data[4] == True and data[5] == True:
            freq_dict["Single-line/Modification/SUCCESS"] = freq_dict["Single-line/Modification/SUCCESS"] + 1
        else:
            freq_dict["Single-line/Modification/FAILURE"] = freq_dict["Single-line/Modification/FAILURE"] + 1
    
    if data[0] == "multi" and data[1] == "insertion":
        if data[3] == True and data[4] == True and data[5] == True:
            freq_dict["Multi-line/Insertion/SUCCESS"] = freq_dict["Multi-line/Insertion/SUCCESS"] + 1
        else:
            freq_dict["Multi-line/Insertion/FAILURE"] = freq_dict["Multi-line/Insertion/FAILURE"] + 1

    if data[0] == "multi" and data[1] == "deletion":
        if data[3] == True and data[4] == True and data[5] == True:
            freq_dict["Multi-line/Deletion/SUCCESS"] = freq_dict["Multi-line/Deletion/SUCCESS"] + 1
        else:
            freq_dict["Multi-line/Deletion/FAILURE"] = freq_dict["Multi-line/Deletion/FAILURE"] + 1
    
    if data[0] == "multi" and data[1] == "modification":
        if data[3] == True and data[4] == True and data[5] == True:
            freq_dict["Multi-line/Modification/SUCCESS"] = freq_dict["Multi-line/Modification/SUCCESS"] + 1
        else:
            freq_dict["Multi-line/Modification/FAILURE"] = freq_dict["Multi-line/Modification/FAILURE"] + 1

print(freq_dict)

output_path = os.path.join(script_dir, "case_study_manual_eval_analysis", f"{LLM}_{DATASET}_freq_dict.json")
with open(output_path, 'w') as output_file:
    json.dump(freq_dict, output_file, indent=4)