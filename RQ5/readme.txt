RQ5 — RAG-based vulnerability localization baseline

Purpose

This folder contains the scripts and materials used for RQ5 in the paper. The main script `test_baseline_rag.py` evaluates a retrieval-augmented (RAG) baseline for localizing vulnerable lines in C functions by combining a BM25 retriever over a local knowledge base with an LLM analysis model (accessed via an Ollama-compatible HTTP API).

Included files

- `test_baseline_rag.py` — evaluation driver that reads a CSV of test functions, optionally performs BM25 retrieval from a JSONL knowledge base, queries the LLM for line-level vulnerability probabilities, and reports Top-1/Top-3/Top-10 accuracy.
- Additional: no bundled knowledge base is included here; reviewers should use the generated samples from `RQ3/` or construct JSONL KB files as described below.

Dependencies

Install the minimal Python packages required to run the evaluation:

  pip install pandas requests rank-bm25

The script requires an Ollama-compatible LLM HTTP endpoint (default URL: `http://localhost:8081/v1/chat/completions`). Ensure you have an Ollama server or a compatible local model server running and accessible at the URL configured by `OLLAMA_ANALYSIS_URL` inside `test_baseline_rag.py`.

Data formats

1) Test CSV (input to the script)

The CSV file must contain at least the following columns (header names are required exactly):

  - `processed_func`     — raw function code used for retrieval (no line numbers)
  - `code_with_lineno`   — the same function but with line numbers prefixed (e.g., "1: int foo() { ... \n2: ...") used in the LLM prompt
  - `flaw_line_index`    — the ground-truth vulnerable line index (integer)

The default CSV path used by the script is `vul_trig_func_loc_with_lineno.csv` in the working directory unless another path is passed as a positional argument.

2) Knowledge base (JSONL files for RAG retrieval)

If you enable RAG (BM25 retrieval), the script expects a directory (pass via `--data-dir`) that contains JSONL files with names ending in `_single.jsonl` or `_multi.jsonl`. Each JSONL line should be a JSON object containing at least:

  - `func`  — the function source code (string) used as the document text for BM25
  - `vulc`  — the vulnerable line indices for that example (array of integers)

Example JSONL entry (one line):

  {"func": "int foo() { ... }", "vulc": [12]}

The script will load files matching `*_single.jsonl` into the "single" KB and `*_multi.jsonl` into the "multi" KB. Use `--rag-type` to choose which KB to query.

Running the evaluation

Basic command (zero-shot, no RAG):

  python RQ5/test_baseline_rag.py path/to/your_test.csv --rag-k 0

Enable RAG with BM25 retrieval (k = number of retrieved examples):

  python RQ5/test_baseline_rag.py path/to/your_test.csv --rag-k 3 --rag-type single --data-dir path/to/jsonl_dir

Notes:
- `--rag-k` (default 3) controls how many examples BM25 retrieves per query. Use `--rag-k 0` to disable retrieval (zero-shot).
- `--rag-type` chooses which KB partition to use (`single` or `multi`). If omitted and `--rag-k` > 0, both types will be evaluated in sequence by the wrapper loop.
- The script uses the model names configured in the script (MODELS_TO_TEST). Edit that list to evaluate other models.

OLLAMA / model server

- The evaluation driver sends chat-completion requests to `OLLAMA_ANALYSIS_URL` (default `http://localhost:8081/v1/chat/completions`). Ensure a compatible LLM server is running and the requested model identifiers are available.
- The script also checks for the `ollama` binary on PATH at start; ensure the Ollama CLI is installed if using Ollama.
- If you cannot run a local model, use pre-generated outputs or run the evaluator with `--rag-k 0` for a model-free smoke test (it will attempt LLM calls if models are in MODELS_TO_TEST).

Expected outputs

- The script prints progress and, at completion, reports Top-1, Top-3, and Top-10 accuracy over the processed set (also shows counts).
- It prints intermediate progress every 10 processed functions.

Performance and hardware

- RAG indexing (BM25) and running the script on small datasets is inexpensive and can be done on a CPU-only machine.
- LLM inference via Ollama may require substantial RAM or GPU depending on model size — for large models use GPU-enabled hosts or use smaller local models.

Troubleshooting

- JSON errors when loading KB files: ensure each line is valid JSON and contains the `func` and `vulc` keys.
- Ollama API errors / timeouts: check that the server is up, reachable at the configured URL, and that the model names in MODELS_TO_TEST are available.
- If `rank_bm25` is missing, install with `pip install rank-bm25`.

Example end-to-end flow (recommended for reviewers)

1) Prepare a small CSV (10–100 rows) with required columns and a compact JSONL KB (a few hundred examples) derived from `RQ3` archives.
2) Start Ollama or a compatible model server and ensure the model(s) you want to test are available.
3) Run the evaluator with `--rag-k 3 --rag-type single --data-dir ../RQ3/kb` and verify the printed Top-N metrics.

License and contact

- This script and the RQ5 materials are provided under the top-level MIT License. For questions or reproduction issues, contact the paper authors listed in the included PDF or raise an issue in the archived repository.