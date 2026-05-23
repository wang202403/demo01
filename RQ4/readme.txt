RQ4 — CVE and vulnerability-detection artifacts

Purpose

This folder contains the artifacts and tool bundles used for RQ4 in the paper. It provides generated CVE-annotated outputs, vulnerability trigger-location mappings, and several third-party or reproduced toolkits used for vulnerability detection and evaluation (LineVul, FVD-DPM, and CodeQL). The materials allow reviewers to test detection tools, reproduce selected experiments, and reuse mapping files for analysis.

Included items

- `CVE_GPT.zip` — Generated CVE-annotated samples produced by our CVE-GPT pipeline. Use these archives as inputs to detection/evaluation pipelines.
- `vul_trig_func_loc.csv` — CSV mapping file listing generated samples and the vulnerable function/trigger location metadata used in evaluations.
- `LineVul-main/` — LineVul tool bundle (code, models, tokenizers, training scripts). See `LineVul-main/LineVul-main/README.md` for project-specific instructions.
- `FVD-DPM-main/` — FVD-DPM project (graph-based diffusion model components and preprocessing). Contains data preprocessing and training code.
- `codeql-main/` — CodeQL tool bundle (upstream CodeQL tree included). Used for static-analysis baselines and for running CodeQL queries.

Dependencies

- Python 3.8+ for Python scripts.
- Common Python packages: numpy, pandas, tqdm, scikit-learn, torch (for LineVul / FVD-DPM), transformers, tokenizers. See each subproject's `requirements.txt` where present (e.g., `LineVul-main/LineVul-main/requirements.txt`).
- System tools:
  - clang-format (optional, used by other RQ scripts)
  - CodeQL CLI (required to run queries in `codeql-main/`)
  - For some graph tools, Neo4j / Joern may be required (see `FVD-DPM-main` README).

Quickstart — Test DL-model performance (LineVul / FVD-DPM)

1) Prepare data:
   - Obtain the original training dataset required by the model (as described in the paper or in the subproject README). Combine the training set with the `CVE_GPT.zip` contents if you want to augment training data with generated CVE examples.
   - Unpack `CVE_GPT.zip` into a working directory: e.g., `Expand-Archive -Path RQ4\CVE_GPT.zip -DestinationPath work\CVE_GPT` (PowerShell) or `unzip RQ4/CVE_GPT.zip -d work/CVE_GPT` (Linux/macOS).

2) Install dependencies for the chosen toolkit, for example LineVul (from repository root):
   - cd `RQ4/LineVul-main/LineVul-main`
   - pip install -r requirements.txt

3) Run training or evaluation on a small subset to confirm environment:
   - Example (LineVul quick-run): see `LineVul-main/LineVul-main/README.md` for exact commands. Use provided saved models in `linevul/saved_models/` for evaluation if present.

Notes:
- Re-training full models may require GPU and several hours; for reviewers we recommend using pre-trained checkpoints included in the subproject or evaluating on a small sample to verify correctness.

Quickstart — Test CodeQL static analysis

1) Install CodeQL CLI following GitHub/CodeQL instructions and ensure `codeql` is available in PATH.
2) Use the `codeql-main/` bundle in this folder or the official CodeQL distribution to run suites. Example (skeleton steps):
   - Create a database for the target source language (see CodeQL docs).
   - Run CodeQL queries or suites against the database. For CWE-specific tests, use the provided `config/suites/security` configuration files (or the equivalent suite files in `codeql-main/`)
   - Example command (high-level):
     codeql database create db --language=cpp --source-root=path/to/sources
     codeql query run --database=db --suite=path/to/config/suites/security

Evaluation checklist for reviewers

- Confirm you can unpack `CVE_GPT.zip` and read `vul_trig_func_loc.csv` to locate vulnerable functions referenced in the paper.
- Run a small evaluation using a pre-trained model or a provided evaluation script (LineVul saved models or FVD-DPM small-run). Verify that outputs are produced and formats match those used in the paper.
- Run CodeQL suites (or selected queries) against a small sample and compare returned alerts to the mapping in `vul_trig_func_loc.csv`.

Hardware and runtime notes

- Training deep models (LineVul, FVD-DPM) requires GPUs. Small-scale verification and evaluation can be done on CPUs but will be slower.
- CodeQL analyses are CPU bound and can be performed on standard workstations; some larger databases may require significant disk space.

Limitations and provenance

- Some components include third-party code (LineVul, FVD-DPM, CodeQL). Review their licenses (in subfolders) before reuse.
- If any generator used proprietary models, only generated outputs are provided; re-generation requires the same model access/credentials.

Contact, license and citation

- For questions, see the paper authors listed in the included PDF or open an issue in the archival repository.
- License: tools and scripts in this folder follow the top-level MIT License unless the subproject specifies a different license (check subfolder LICENSE files).