import os
import json
import random
from collections import OrderedDict

# CASE STUDIES: STEP 1.

# >>>>> Create a dictionary for storing file data. <<<<<

# Specify the folder path.
script_dir = os.path.dirname(__file__)
LLM = "CodeLLaMa"
DATASET = "SARD"
folder_path = os.path.join(script_dir, LLM, DATASET)
# folder_path = os.path.join(script_dir, LLM, DATASET, "results_unprocessed")

# Number of samples to evaluate for the SARD dataset.
if DATASET == "SARD": N = 5000
# Create a list of all files in the folder.
file_list = os.listdir(folder_path)
# Randomly select N files from the folder.
selected_files = random.sample(file_list, N)

# Create a dictionary to store size of change, type of change, and type of response data.
change_size = ""          # Single-line or Multi-line
change_type = ""          # Insertion, Deletion, or Modification
partial_response = False  # Was all of the code copied over in the response or not?

case_study_dict = {}
for file_name in selected_files:
    case_study_dict[file_name] = [change_size, change_type, partial_response]

# Order the dictionary alphabetically by file name.
case_study_dict = OrderedDict(sorted(case_study_dict.items()))

# Save the ordered dictionary to a JSON file.
output_file = f'{LLM}_{DATASET}_case_study.json'
output_path = os.path.join(script_dir, "case_studies", output_file)
with open(output_path, 'w') as json_file:
    json.dump(case_study_dict, json_file, indent=4)