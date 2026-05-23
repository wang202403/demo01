RQ1 — Sample generation and analysis

Purpose

This directory implements the sample generation and analysis workflows used for RQ1 in the paper. It contains the main driver script `generate_sample.py` (supports standard, few_shot, and cot modes), several helper scripts for preprocessing and statistics, and a `generated_samples/` directory with pre-generated model outputs.

Required files

- `generate_sample.py` — main script to generate injected vulnerable samples from input C files.
- `cwe_vulnerabilities_with_updated_reasoning_v2.json` — exemplar JSON (expected by default). Place this file in the `RQ1/` folder or update `EXEMPLARS_JSON_FILE` in the script.
- `generated_samples/` — (optional) pre-generated archives for each model/experiment. Use these when GPU / model API is not available.
- Output and debug folders are created automatically (`OUTPUT/` and `DEBUG_LOGS/`).

Dependencies

Install core Python packages (see repository root README for full list). Minimum required for RQ1 scripts:

  pip install requests numpy pandas tqdm

Optional (only for running heavy model inference locally): install and run a local model server that supports the simple completion API used by the script (default URL: `http://localhost:8081/v1/completions`).

Configuration

- API endpoint: edit `DOCKER_API_URL` at the top of `generate_sample.py` if your local model server uses a different address.
- Exemplars file: set `EXEMPLARS_JSON_FILE` or place the exemplar JSON file in `RQ1/`.
- Token / model limits: `MODEL_TOKEN_LIMITS` and `DEFAULT_TOKEN_CONFIG` in the script can be adjusted for your model.

Usage examples

1) Print extended examples and help:

  python RQ1/generate_sample.py --examples

2) Standard mode (single-file injections). Processes up to N .c files in the input directory and generates `_injected.c` outputs:

  python RQ1/generate_sample.py --mode standard --input_dir <INPUT_DIR> --output_dir <OUTPUT_DIR> --max_files 5

3) Few-shot mode (in-context learning with exemplars, fast to validate using pre-generated exemplars):

  python RQ1/generate_sample.py --mode few_shot --input_dir <INPUT_DIR> --output_dir <OUTPUT_DIR> --max_files_per_cwe 20

4) Chain-of-thought (cot) mode — same as few_shot but enables COT; may increase token usage and API calls:

  python RQ1/generate_sample.py --mode cot --input_dir <INPUT_DIR> --output_dir <OUTPUT_DIR> --max_files_per_cwe 10

5) Override generation token limit:

  python RQ1/generate_sample.py --mode few_shot --max_gen 2048 --input_dir <INPUT_DIR> --output_dir <OUTPUT_DIR>

Notes and tips

- If you do not have a local model server or GPU, prefer using the archives in `generated_samples/` and run the analysis / statistics scripts that read those archives.
- Debug logs are written to `DEBUG_LOGS/` and include prompts, intermediate summaries, and model responses. Use these logs for troubleshooting.
- Output layout: results are saved under `<output_dir>/<mode>/<input_folder>_model_name/` with `_injected.c` suffix on generated files.
- The script will skip files that already end with `_vul.c` and will only process `.c` files.

Contact

For problems reproducing RQ1 experiments, consult the repository-level README first. If issues remain, contact the paper authors (see included paper PDF) or open an issue in the archived repository.

License

This directory and scripts are distributed under the MIT License (see top-level `LICENSE`).