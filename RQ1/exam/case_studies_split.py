import os
import json
import shutil

# CASE STUDIES: STEP 4.

LLM = "CodeLLaMa"
DATASET = "SARD"
script_dir = os.path.dirname(__file__)

# Open the .json file corresponding to the Case Study data for the LLM and dataset.
case_study_path = os.path.join(script_dir, "case_studies", f"{LLM}_{DATASET}_case_study.json")
with open(case_study_path, 'r') as input_file:
    data = input_file.read()
case_study = json.loads(data)

# Get results_processed folder path corresponding to this LLM and dataset.
results_processed_path = os.path.join(script_dir, LLM, DATASET)

# Get the output paths for the Single-line & Multi-line data.
single_line_path = os.path.join("training_2", LLM, DATASET, "Single-line")
multi_line_path = os.path.join("training_2", LLM, DATASET, "Multi-line")

for file_name, data in case_study.items():

    # If the data is a partial or failed response, skip the file.
    if data[2] == "True":
        continue
    if data[0] == "False" and data[1] == "False" and data[2] == "False":
        continue

    file_path = os.path.join(results_processed_path, file_name)
    if data[0] == "single":
        output_path = os.path.join(single_line_path, file_name)
    elif data[0] == "multi":
        output_path = os.path.join(multi_line_path, file_name)
    try:
        shutil.copy(file_path, output_path)
    except Exception as e:
        print(f"Error copying {file_name}: {e}")
        continue