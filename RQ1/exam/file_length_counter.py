import os

script_dir = os.path.dirname(__file__)
input_path = os.path.join(script_dir, "GPT-4o", "CVE-LLM", "results_unprocessed")
input_files = os.listdir(input_path)

print(f"Folder Length: {len(input_files)}")

for file in input_files:
    input_file_path = os.path.join(input_path, file)
    with open(input_file_path, 'r') as input_file:
        file_len = len(input_file.readlines())
        if file_len < 5:
            print(f"File failed: {file}, File length: {file_len}")