#!/usr/bin/env python3
import os
import re
import json
import argparse
import requests

####################################
# Configuration Parameters
####################################
# Default parameter for standard mode
DEFAULT_MAX_FILES_STANDARD = 2

# Parameters for FS (few_shot/cot) mode
EXEMPLARS_JSON_FILE = "cwe_vulnerabilities_with_updated_reasoning_v2.json"  # Example JSON file
DEBUG_LOG_DIR = "./DEBUG_LOGS"     # Base directory for debug logs
DOCKER_API_URL = "http://localhost:8081/v1/completions"  # Docker model API URL
MAX_CODE_LENGTH = 200  # If code exceeds this length, perform additional processing
COT_OPEN = False       # In few_shot mode, chain-of-thought (cot) is off by default; set to True in cot mode

# Token configuration
DEFAULT_TOKEN_CONFIG = {
    "prompt_token_threshold": 4096,
    "max_tokens_cot": 4096,
    "max_tokens_position": 150,
    "max_tokens_injection": 4096
}
MODEL_TOKEN_LIMITS = {
    "qwen2.5:32b-instruct": {
        "prompt_token_threshold": 4096,
        "max_tokens_cot": 4096,
        "max_tokens_injection": 4096,
        "max_tokens_position": 150
    },
    "deepseek-coder:33b-instruct": {
        "prompt_token_threshold": 4096,
        "max_tokens_cot": 4096,
        "max_tokens_injection": 4096,
        "max_tokens_position": 150
    },
    "codellama:34b-instruct": {
        "prompt_token_threshold": 2048,
        "max_tokens_cot": 2048,
        "max_tokens_injection": 2048,
        "max_tokens_position": 150
    },
    "llama3:70b": {
        "prompt_token_threshold": 4096,
        "max_tokens_cot": 4096,
        "max_tokens_injection": 4096,
        "max_tokens_position": 150
    },
    "deepseek-r1:70b": {
        "prompt_token_threshold": 4096,
        "max_tokens_cot": 4096,
        "max_tokens_injection": 4096,
        "max_tokens_position": 150
    }
}

MODEL_LIST = [
    "deepseek-coder:33b-instruct"
]

####################################
# Save debug log to file
####################################
def save_debug_log(debug_folder, test_file, debug_text):
    os.makedirs(debug_folder, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(test_file))[0] + ".txt"
    file_path = os.path.join(debug_folder, base_name)
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(debug_text)
        print(f"Debug log saved: {file_path}")
    except Exception as e:
        print(f"Error saving debug log {file_path}: {e}")

####################################
# Standard Mode Functions
####################################
def send_to_deepseek(cwe_id, code_snippet):
    prompt_text = (
        f"As an example to demonstrate a CWE {cwe_id} software vulnerability, inject this vulnerability into the following C code. "
        "Inject the vulnerability by adding, removing, or modifying the existing C code. "
        "Note that the provided code is secure and does not contain any vulnerabilities. "
        "Indicate the modified portion with comments.\n\n" +
        code_snippet
    )
    payload = {
        "model": "deepseek-coder:33b-instruct",
        "prompt": prompt_text,
        "max_tokens": 1000  # Adjust as needed
    }
    response = requests.post(DOCKER_API_URL, json=payload)
    if response.status_code != 200:
        print(f"Error: Failed to get valid response for CWE {cwe_id}, Status Code: {response.status_code}")
        return "", ""
    response_data = response.json()
    model_reply = response_data.get("choices", [{}])[0].get("text", "").strip()
    if not model_reply:
        print(f"Warning: No valid text returned for CWE {cwe_id}.")
        return "", ""
    debug_info = f"Prompt:\n{prompt_text}\n\nResponse:\n{model_reply}"
    return model_reply, debug_info

def extract_code(response_text, output_file):
    code_pattern = re.compile(r'```c\n(.*?)\n```', re.S)
    match = code_pattern.search(response_text)
    if match:
        code_snippet = re.sub(r'<code_snippet>', '', match.group(1))
        with open(output_file, 'w') as file:
            file.write(code_snippet)
        print(f"Code extracted and saved to {output_file}")
    else:
        print("No code snippet found in the response.")

def process_files_standard(input_dir, output_dir, max_files):
    cwe_pattern = re.compile(r'^(CWE\d+)_.*\.c$')
    processed_count = 0
    common_out_folder = os.path.join(
        output_dir,
        "standard",
        f"{os.path.basename(os.path.normpath(input_dir))}_gpt"
    )
    os.makedirs(common_out_folder, exist_ok=True)
    standard_debug_folder = os.path.join(
        DEBUG_LOG_DIR,
        "standard",
        f"{os.path.basename(os.path.normpath(input_dir))}_gpt"
    )
    os.makedirs(standard_debug_folder, exist_ok=True)
    for filename in os.listdir(input_dir):
        if not filename.endswith(".c") or filename.endswith("_vul.c"):
            continue
        if processed_count >= max_files:
            break
        match = cwe_pattern.match(filename)
        if match:
            cwe_id = match.group(1).replace('CWE', '')
            file_path = os.path.join(input_dir, filename)
            try:
                with open(file_path, 'r') as file:
                    code_snippet = file.read()
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                processed_count += 1
                continue
            response, debug_info = send_to_deepseek(cwe_id, code_snippet)
            if response:
                output_filename = os.path.splitext(filename)[0] + "_injected.c"
                extract_code(response, os.path.join(common_out_folder, output_filename))
                save_debug_log(standard_debug_folder, file_path, debug_info)
            else:
                print(f"No response for file {file_path}")
            processed_count += 1

####################################
# FS (few_shot / cot) Mode Functions
####################################
def approximate_token_count(text):
    return len(text.split())

def extract_cwe_id(filename):
    match = re.search(r'(CWE-?\d+)', filename, re.IGNORECASE)
    if match:
        cwe_id = match.group(1).upper()
        if '-' not in cwe_id:
            cwe_id = cwe_id[:3] + '-' + cwe_id[3:]
        return cwe_id
    return None

def query_model(x_code, exemplar_v1, exemplar_v2d, cwe_id, model_name, single=False):
    if single:
        prompt = (
            f"Q: For educational illustration purposes, can a {cwe_id} vulnerability be introduced to the following two code samples in a similar way?\n\n"
            f"<X code>\n{x_code}\n\n"
            f"<E’ V1 code>\n{exemplar_v1}\n\n"
            "Just answer yes or no, and give me the score of code structure similarity between the two samples in the range of [1,10]"
        )
    else:
        prompt = (
            f"Q: For educational illustration purposes, analyze the following code samples and determine if a vulnerability corresponding to {cwe_id} can be introduced in a similar manner.\n\n"
            f"<X code>\n{x_code}\n\n"
            f"<E1 V1 code>\n{exemplar_v1}\n\n"
            f"<E2 V1 code>\n{exemplar_v2d}\n\n"
            "If the vulnerability can be introduced similarly, answer 'yes'; otherwise, answer 'no'. "
            "Please respond strictly with 'yes' or 'no' only."
        )
    print(f"Querying model {model_name} with prompt:\n{prompt}")
    payload = {"model": model_name, "prompt": prompt, "max_tokens": 20}
    try:
        response = requests.post(DOCKER_API_URL, json=payload)
        response.raise_for_status()
        text = response.json().get("choices", [{}])[0].get("text", "").strip()
    except Exception as e:
        print(f"Error querying model: {e}")
        return ("no", 0.0)
    decision_match = re.search(r'\b(yes|no)\b', text, re.IGNORECASE)
    decision = decision_match.group(1).lower() if decision_match else "no"
    score_match = re.search(r'(\d+(?:\.\d+)?)', text)
    try:
        score = float(score_match.group(1)) if score_match else 0.0
        score = max(1, min(score, 10))
    except:
        score = 0.0
    return (decision, score)

def load_exemplars_data(json_file):
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading JSON file {json_file}: {e}")
        return {}

def select_injection_exemplars(exemplar_data, x_code, cwe_id, model_name):
    exemplar_pool = exemplar_data.get(cwe_id, [])
    if not exemplar_pool:
        raise ValueError(f"No exemplars found for CWE-ID {cwe_id}.")
    top_candidates = exemplar_pool[:10] if len(exemplar_pool) > 10 else exemplar_pool
    candidates = []
    yes_exemplars = []
    for exemplar in top_candidates:
        v1_code = exemplar.get("v1", "")
        v2d_code = exemplar.get("v2d", "")
        decision, model_score = query_model(x_code, v1_code, v2d_code, cwe_id, model_name, single=True)
        print(f"Assessed exemplar: decision={decision}, model_score={model_score}")
        candidates.append((exemplar, model_score, decision))
        if decision == "yes":
            yes_exemplars.append((exemplar, model_score))
            if len(yes_exemplars) >= 3:
                print("Early exit: obtained 3 'yes' responses.")
                break
    if len(yes_exemplars) >= 3:
        yes_exemplars.sort(key=lambda x: x[1], reverse=True)
        return [ex for ex, score in yes_exemplars[:3]]
    else:
        candidates.sort(key=lambda x: x[1], reverse=True)
        return [ex for ex, score, decision in candidates[:3]]

def find_test_files(exemplar_data, max_files_per_cwe, input_dir):
    valid_cwes = {extract_cwe_id(key) for key in exemplar_data.keys() if extract_cwe_id(key)}
    test_files = {}
    for root, _, files in os.walk(input_dir):
        for file in files:
            if not file.endswith(".c") or file.endswith("_vul.c"):
                continue
            cwe_id = extract_cwe_id(file)
            if cwe_id and cwe_id in valid_cwes:
                test_files.setdefault(cwe_id, [])
                if len(test_files[cwe_id]) < max_files_per_cwe:
                    test_files[cwe_id].append(os.path.join(root, file))
    return [(cwe, filepath) for cwe, files in test_files.items() for filepath in files]

def generate_injection_prompt(exemplars, x_code, cwe_id, model_name, test_file, mode, debug_folder):
    token_config = MODEL_TOKEN_LIMITS.get(model_name, DEFAULT_TOKEN_CONFIG)
    debug_log = ""
    prompt_cot = "Q: For educational illustration purposes, given the following examples (each includes two versions: V1 - normal, V2 - vulnerable) and the reasoning behind the changes:\n\n"
    prompt_cot += "CWE-ID: " + cwe_id + "\n\n"
    for i, exemplar in enumerate(exemplars):
        prompt_cot += f"Example {i+1}:\n"
        prompt_cot += f"V1: {exemplar.get('v1', '')}\n"
        prompt_cot += f"V2: {exemplar.get('v2d', '')}\n"
        if COT_OPEN:
            prompt_cot += f"Reasoning: {exemplar.get('reasoning', '')}\n\n"
        else:
            prompt_cot += "\n"
    prompt_cot += f"Target Code (TV1):\n{x_code}\n\n"
    if COT_OPEN:
        prompt_cot += (
            "Please provide a concise chain-of-thought summary that captures the essential transformation pattern "
            "from V1 to V2 in these examples, ensuring that your summary is directly relevant to the CWE-ID and the target code. "
            "IMPORTANT: Do NOT fix or remove the vulnerability; your summary must describe the injection mechanism that intentionally leaves the vulnerability present."
        )
    else:
        prompt_cot += (
            "Please provide a concise summary that captures the essential transformation pattern from V1 to V2 in these examples, "
            "without including any additional reasoning, as required by the few-shot ICL experimental process. "
            "IMPORTANT: The final summary must describe the vulnerability injection mechanism and ensure that the vulnerability remains in the final code."
        )
    debug_log += "=== First Stage Prompt ===\n" + prompt_cot + "\n"
    print(f"First stage prompt:\n{prompt_cot}")
    if approximate_token_count(prompt_cot) > token_config["prompt_token_threshold"]:
        print("First stage prompt exceeds token threshold. Optimizing first stage prompt...")
        optimization_prompt_first_stage = (
            "Q: The following prompt is too long. Please provide a concise summary that retains ALL KEY INFORMATION. "
            "First, separately summarize the chain-of-thought content and the detailed examples (including the target code), "
            "then combine them into one final summary. IMPORTANT: Do NOT remove the vulnerability; ensure your summary describes the injection mechanism that leaves the vulnerability intact.\n\n" + prompt_cot
        )
        debug_log += "=== First Stage Optimization Prompt ===\n" + optimization_prompt_first_stage + "\n"
        payload_opt = {"model": model_name, "prompt": optimization_prompt_first_stage, "max_tokens": token_config["max_tokens_cot"]}
        try:
            response = requests.post(DOCKER_API_URL, json=payload_opt)
            response.raise_for_status()
            prompt_cot = response.json().get("choices", [{}])[0].get("text", "").strip()
            debug_log += "=== Optimized First Stage Prompt ===\n" + prompt_cot + "\n"
            print("Optimized first stage prompt:\n", prompt_cot)
        except Exception as e:
            print("Error optimizing first stage prompt:", e)
            debug_log += "Error optimizing first stage prompt: " + str(e) + "\n"
    payload_cot = {"model": model_name, "prompt": prompt_cot, "max_tokens": token_config["max_tokens_cot"]}
    try:
        response = requests.post(DOCKER_API_URL, json=payload_cot)
        response.raise_for_status()
        cot_summary = response.json().get("choices", [{}])[0].get("text", "").strip()
    except Exception as e:
        print(f"Error generating summary: {e}")
        debug_log += "Error generating summary: " + str(e) + "\n"
        cot_summary = ""
    debug_log += "=== Summary ===\n" + cot_summary + "\n"
    injection_position = ""
    if len(x_code) > MAX_CODE_LENGTH:
        prompt_position = (
            f"Q: Using the following summary:\n{cot_summary}\n\n"
            f"CWE-ID: {cwe_id}\n\n"
            f"and the following code:\n{x_code}\n\n"
            "Please identify the most appropriate location within the code to inject a vulnerability corresponding to the summarized pattern. "
            "Provide a brief explanation and specify the injection position (e.g., line number or code context snippet)."
        )
        debug_log += "=== Injection Position Prompt ===\n" + prompt_position + "\n"
        print(f"Injection position prompt:\n{prompt_position}")
        payload_position = {"model": model_name, "prompt": prompt_position, "max_tokens": token_config["max_tokens_position"]}
        try:
            response = requests.post(DOCKER_API_URL, json=payload_position)
            response.raise_for_status()
            injection_position = response.json().get("choices", [{}])[0].get("text", "").strip()
        except Exception as e:
            print(f"Error generating injection position: {e}")
            debug_log += "Error generating injection position: " + str(e) + "\n"
        debug_log += "=== Injection Position Result ===\n" + injection_position + "\n"
        verification_prompt = (
            f"Q: Please verify the following injection position details and confirm its correctness. "
            f"If it is valid, simply answer 'confirmed'. If not, provide a corrected injection position with explanation, ensuring all key information is preserved.\n\nInjection Position: {injection_position}"
        )
        debug_log += "=== Injection Position Verification Prompt ===\n" + verification_prompt + "\n"
        print(f"Injection position verification prompt:\n{verification_prompt}")
        payload_ver = {"model": model_name, "prompt": verification_prompt, "max_tokens": token_config["max_tokens_position"]}
        try:
            response = requests.post(DOCKER_API_URL, json=payload_ver)
            response.raise_for_status()
            verification_result = response.json().get("choices", [{}])[0].get("text", "").strip()
            if verification_result.lower() != "confirmed":
                injection_position = verification_result
            debug_log += "=== Injection Position Verification Result ===\n" + verification_result + "\n"
        except Exception as e:
            print(f"Error verifying injection position: {e}")
            debug_log += "Error verifying injection position: " + str(e) + "\n"
    if injection_position:
        prompt_injection = (
            f"Q: Based on the following summary:\n{cot_summary}\n\n"
            f"CWE-ID: {cwe_id}\n\n"
            f"and the verified injection position (please confirm the following injection position details again: {injection_position}),\n\n"
            "please modify the following code (TV1) to inject the corresponding vulnerability exactly as described in the summary. "
            "IMPORTANT: DO NOT fix or remove the vulnerability; your output MUST explicitly include the vulnerability. "
            "Return the complete modified code without any explanation.\n\nTV1: {x_code}\n\nTV2: "
        ).replace("{x_code}", x_code)
    else:
        prompt_injection = (
            f"Q: Using the following summary of vulnerability injection pattern:\n{cot_summary}\n\n"
            f"CWE-ID: {cwe_id}\n\n"
            "Now, for the following code version TV1, generate the corresponding TV2 code. "
            "IMPORTANT: DO NOT fix or remove the vulnerability; your output MUST explicitly include the vulnerability as described. "
            "Only provide the code, without any explanation.\n\nTV1: {x_code}\n\nTV2: "
        ).replace("{x_code}", x_code)
    debug_log += "=== Injection Prompt Before Optimization ===\n" + prompt_injection + "\n"
    print(f"Injection prompt before optimization:\n{prompt_injection}")
    if approximate_token_count(prompt_injection) > token_config["prompt_token_threshold"]:
        optimization_prompt = (
            f"Q: The current summary is as follows:\n{cot_summary}\n\n"
            f"And the injection prompt is as follows:\n{prompt_injection}\n\n"
            "Please first separately summarize the summary and the injection position details, ensuring ALL KEY INFORMATION is preserved. "
            "Then combine them into one optimized summary that reduces the total token count below 6000. Provide only the optimized summary."
        )
        debug_log += "=== Injection Prompt Optimization Prompt ===\n" + optimization_prompt + "\n"
        payload_opt_injection = {"model": model_name, "prompt": optimization_prompt, "max_tokens": token_config["max_tokens_cot"]}
        try:
            response = requests.post(DOCKER_API_URL, json=payload_opt_injection)
            response.raise_for_status()
            optimized_cot_summary = response.json().get("choices", [{}])[0].get("text", "").strip()
        except Exception as e:
            print(f"Error generating optimized summary: {e}")
            debug_log += "Error generating optimized summary: " + str(e) + "\n"
            optimized_cot_summary = cot_summary
        if injection_position:
            prompt_injection = (
                f"Q: Based on the following optimized summary:\n{optimized_cot_summary}\n\n"
                f"CWE-ID: {cwe_id}\n\n"
                f"and the verified injection position (again, {injection_position}),\n\n"
                "please modify the following code (TV1) to inject the corresponding vulnerability at the specified location. "
                "IMPORTANT: DO NOT fix or remove the vulnerability; your output MUST explicitly include the vulnerability as described. "
                "Return the complete modified code without any explanation.\n\nTV1: {x_code}\n\nTV2: "
            ).replace("{x_code}", x_code)
        else:
            prompt_injection = (
                f"Q: Using the following optimized summary of vulnerability injection pattern:\n{optimized_cot_summary}\n\n"
                f"CWE-ID: {cwe_id}\n\n"
                "Now, for the following code version TV1, generate the corresponding TV2 code. "
                "IMPORTANT: DO NOT fix or remove the vulnerability; your output MUST explicitly include the vulnerability as described. "
                "Only provide the code, without any explanation.\n\nTV1: {x_code}\n\nTV2: "
            ).replace("{x_code}", x_code)
        debug_log += "=== Optimized Injection Prompt ===\n" + prompt_injection + "\n"
        print(f"Optimized injection prompt:\n{prompt_injection}")
    final_attempt = 0
    injected_code = ""
    while final_attempt < 2:
        payload_injection = {"model": model_name, "prompt": prompt_injection, "max_tokens": token_config["max_tokens_injection"]}
        try:
            response = requests.post(DOCKER_API_URL, json=payload_injection)
            response.raise_for_status()
            injected_code = response.json().get("choices", [{}])[0].get("text", "").strip()
        except Exception as e:
            print(f"Error generating injection code: {e}")
            debug_log += "Error generating injection code: " + str(e) + "\n"
            injected_code = ""
        if injected_code.lower() == "no" or not injected_code:
            feedback_prompt = (
                f"Q: The previously generated code appears to be incorrect or missing. Based on the following intermediate results:\n"
                f"Summary: {cot_summary}\n"
                f"Verified Injection Position: {injection_position}\n"
                f"Original Injection Prompt: {prompt_injection}\n\n"
                "Please revise and generate the complete modified code (TV2) again, ensuring that all key information is incorporated and that the vulnerability remains present (do not fix the vulnerability)."
            )
            debug_log += "=== Feedback Revision Prompt ===\n" + feedback_prompt + "\n"
            print(f"Feedback revision prompt:\n{feedback_prompt}")
            payload_feedback = {"model": model_name, "prompt": feedback_prompt, "max_tokens": token_config["max_tokens_injection"]}
            try:
                response = requests.post(DOCKER_API_URL, json=payload_feedback)
                response.raise_for_status()
                injected_code = response.json().get("choices", [{}])[0].get("text", "").strip()
                debug_log += "=== Revision Response ===\n" + injected_code + "\n"
            except Exception as e:
                print(f"Error in feedback revision: {e}")
                debug_log += "Error in feedback revision: " + str(e) + "\n"
                injected_code = ""
        else:
            break
        final_attempt += 1
    debug_log += "=== Final Injection Prompt ===\n" + prompt_injection + "\n"
    debug_log += "=== Model Final Response (Injected Code) ===\n" + injected_code + "\n"
    save_debug_log(debug_folder, test_file, debug_log)
    return injected_code

####################################
# Main Function: Uses --input_dir and --output_dir parameters
####################################
def print_usage_examples():
    """Print extended usage examples and instructions for common workflows."""
    examples = """
Usage examples for generate_sample.py

1) Basic standard mode (process up to N C files in SARD_OUT):
   python RQ1/generate_sample.py --mode standard --input_dir SARD_OUT --output_dir OUTPUT --max_files 5

2) Few-shot mode using exemplars JSON and preconfigured model list (uses MODEL_LIST in script):
   python RQ1/generate_sample.py --mode few_shot --input_dir SARD_OUT --output_dir OUTPUT --max_files_per_cwe 20

3) Chain-of-thought (cot) mode (turns on internal COT behavior, may increase token usage):
   python RQ1/generate_sample.py --mode cot --input_dir SARD_OUT --output_dir OUTPUT --max_files_per_cwe 10

4) Override default generation token limit:
   python RQ1/generate_sample.py --mode few_shot --max_gen 2048 --input_dir SARD_OUT --output_dir OUTPUT

Notes:
 - The script expects exemplar data in the file defined by EXEMPLARS_JSON_FILE (default: cwe_vulnerabilities_with_updated_reasoning_v2.json).
 - The script sends requests to a local model API defined by DOCKER_API_URL (default: http://localhost:8081/v1/completions). Ensure your model endpoint is running and accessible.
 - Debug logs are saved under the DEBUG_LOG_DIR directory.
 - For heavy-model experiments, prefer using pre-generated archives in RQ1/generated_samples/ to save time.

"""
    print(examples)


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability injection script: supports standard, few_shot, and cot modes",
        epilog=("Examples: see --examples for extended usage examples. "
                "Typical commands:\n  python RQ1/generate_sample.py --mode standard --input_dir SARD_OUT --output_dir OUTPUT\n")
    )
    parser.add_argument('--examples', action='store_true', help='Print extended usage examples and exit')
    parser.add_argument('--mode', choices=['standard', 'few_shot', 'cot'], default='standard',
                        help='Output mode: standard (single-file injections), few_shot (ICL few-shot generation), or cot (few_shot with chain-of-thought enabled)')
    parser.add_argument('--max_gen', type=int, default=None, help='Maximum token generation limit (overrides default token limits)')
    parser.add_argument('--input_dir', type=str, default="SARD_OUT", help='Input directory containing .c test files')
    parser.add_argument('--output_dir', type=str, default="OUTPUT", help='Output directory (results will be saved in {output_dir}/{mode}/{input_folder}_model_name)')
    parser.add_argument('--max_files', type=int, default=DEFAULT_MAX_FILES_STANDARD,
                        help='Maximum number of files to process in standard mode (default: %(default)s)')
    parser.add_argument('--max_files_per_cwe', type=int, default=50,
                        help='Maximum number of files per CWE in few_shot/cot mode (default: %(default)s)')
    args = parser.parse_args()

    # If user requested extended usage examples, print and exit
    if args.examples:
        print_usage_examples()
        return

    if args.max_gen:
        DEFAULT_TOKEN_CONFIG["max_tokens_injection"] = args.max_gen
        for model in MODEL_TOKEN_LIMITS:
            MODEL_TOKEN_LIMITS[model]["max_tokens_injection"] = args.max_gen

    if args.mode == "standard":
        if os.path.isdir(args.input_dir):
            process_files_standard(args.input_dir, args.output_dir, args.max_files)
        else:
            print("Invalid input directory.")
    elif args.mode in ["few_shot", "cot"]:
        global COT_OPEN
        COT_OPEN = (args.mode == "cot")
        exemplar_data = load_exemplars_data(EXEMPLARS_JSON_FILE)
        test_files = find_test_files(exemplar_data, args.max_files_per_cwe, args.input_dir)
        common_out_folder = os.path.join(
            args.output_dir,
            args.mode,
            f"{os.path.basename(os.path.normpath(args.input_dir))}_model_name"
        )
        os.makedirs(common_out_folder, exist_ok=True)
        common_debug_folder = os.path.join(
            DEBUG_LOG_DIR,
            args.mode,
            f"{os.path.basename(os.path.normpath(args.input_dir))}_model_name"
        )
        os.makedirs(common_debug_folder, exist_ok=True)
        for model in MODEL_LIST:
            current_model = model
            for cwe_id, test_file in test_files:
                try:
                    with open(test_file, 'r', encoding='utf-8') as f:
                        x_code = f.read()
                except Exception as e:
                    print(f"Error reading file {test_file}: {e}")
                    continue
                try:
                    injection_exemplars = select_injection_exemplars(exemplar_data, x_code, cwe_id, current_model)
                    print(f"Selected {len(injection_exemplars)} exemplar(s) for injection.")
                except Exception as e:
                    print(f"Error selecting exemplars for {cwe_id}: {e}")
                    continue
                injected_code = generate_injection_prompt(injection_exemplars, x_code, cwe_id, current_model, test_file, args.mode, common_debug_folder)
                output_filename = os.path.splitext(os.path.basename(test_file))[0] + "_injected.c"
                output_path = os.path.join(common_out_folder, output_filename)
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        f.write(injected_code)
                    print(f"Saved injected file: {output_path}")
                except Exception as e:
                    print(f"Error writing file {output_path}: {e}")
    else:
        print("Invalid mode selected.")


if __name__ == '__main__':
    main()
