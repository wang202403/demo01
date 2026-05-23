RQ3 — Generation tool outputs and evaluation

Purpose

This folder contains the artifacts related to RQ3 in the paper: outputs and archives produced by the automated vulnerability generation tools evaluated in the study. The materials allow reviewers to inspect generated samples, rerun simple analyses, and reuse generated data for downstream evaluation.

Included files

- `VGX.zip` — archive containing outputs produced by the VGX generation pipeline used in the paper. Inspect for generated source files, metadata (e.g., mapping between original file and generated sample), and any evaluation logs.
- `VulGen.zip` — archive containing outputs produced by the VulGen generation pipeline used in the paper. Inspect similarly for generated samples, metadata, and logs.
- `readme.txt` — this file.

Provenance

- Generated outputs were produced by running the corresponding generation tools and configurations described in the paper. Each archive contains internal metadata (JSON/CSV files) that document which prompts/configuration produced each generated sample. If you need the original generator code (not included), contact the authors or review the per-tool subfolders if present.

Dependencies

- Minimal: Python 3.8+ (for any analysis scripts you may run locally), a tool to unzip archives (built-in OS tools or `unzip`/PowerShell Expand-Archive).
- If you plan to re-run any generator code (if included), consult the archive for a `requirements.txt` or a README inside the zip. Large-model re-generation may require GPU and the model runtimes used in the paper.

How to inspect the archives (quick steps)

On Windows PowerShell (example):

1) Create a working folder and extract the archive:
   mkdir .\rq3_work; Expand-Archive -Path .\RQ3\VGX.zip -DestinationPath .\rq3_work\VGX

2) List extracted files:
   Get-ChildItem -Recurse .\rq3_work\VGX | Select-Object FullName, Length

3) Open any metadata files (JSON/CSV) with a text editor or Python/pandas for analysis. Example Python quick-check:

   python - <<'PY'
import json, csv, os
p = 'rq3_work/VGX/metadata.json'
if os.path.exists(p):
    with open(p,'r',encoding='utf-8') as f:
        meta = json.load(f)
    print('Metadata keys:', list(meta.keys())[:10])
else:
    print('No metadata.json found; list files')
    print(os.listdir('rq3_work/VGX'))
PY

Reproducing RQ3 analysis

1) Prefer using the provided generated archives rather than re-running large generators (which may require model access / GPUs). Use the included metadata and inspection scripts in the repository (or write small pandas scripts) to compute the same summary statistics reported in the paper (counts per CWE, length distributions, edit types, etc.).

2) Typical analysis steps:
   - Unpack the archive(s).
   - Locate metadata CSV/JSON describing sample ids, source file, CWE, prompt, and generator settings.
   - Run the evaluation/statistics scripts from the repository that accept a directory of generated samples (see root README and RQ1 for reusable scripts). For example, adapt scripts in `RQ1/` to parse these archives if formats match.

Evaluation checklist for reviewers

- Confirm that each archive can be unpacked and contains sample files and metadata.
- Verify that metadata contains enough provenance to link each generated sample to the prompt/configuration used.
- Run a small-scale analysis (e.g., count samples per CWE, distribution of sample lengths) and compare with the paper tables/figures.
- If the generator code is included and you re-run generation, use a small subset and compare results to pre-generated outputs to verify reproducibility.

Notes and limitations

- The archives may be large. Use the pre-generated samples for evaluation when computational resources are limited.
- If any proprietary model or paid API was required to produce the archives, the archive contains the generated outputs but not the proprietary model; re-generation will require access to the same model and credentials.

Contact and license

- For questions about RQ3 artifacts, consult the paper authors listed in the included PDF or open an issue in the archival repository.
- These generated-sample archives and accompanying scripts in the repository are distributed under the MIT License (see top-level `LICENSE`).

