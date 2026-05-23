RQ2 — Dataset splitting and small-change classification

Purpose

This folder contains tools used in RQ2 for classifying code edits and preparing split datasets. It includes two main scripts:

- `divide_edit.py` — classifies change types between paired files named `vul.c` and `fixed.c` inside subfolders and prints per-pair classifications. Can produce a simple summary when run with the CLI options.
- `divide_sm.py` — normalizes C source files with `clang-format`, classifies pairs of files named `<base>_injected.c` and `<base>_fixed.c` into categories (single-line small changes, multi-line changes, comment-only changes, or no changes), and moves paired files into corresponding destination folders under the same directory.

Required files

- A directory containing subfolders of pair files for `divide_edit.py`, where each subfolder should contain `vul.c` and `fixed.c`.
- A flat directory containing paired files for `divide_sm.py` with filenames following the pattern `<base>_injected.c` and `<base>_fixed.c` (both files present for each base).
- `clang-format` (required for `divide_sm.py`). Ensure it is installed and available on PATH.

Dependencies

Both scripts use only Python standard library modules except for `divide_sm.py` which shells out to `clang-format`.

Minimum Python requirements: Python 3.7+

Usage — divide_edit.py

This script compares `vul.c` and `fixed.c` in each subfolder and classifies the change as one of: `add`, `del`, `replace`, `no change`, or `error`.

CLI options:
  --dir, -d <path>   Path to the main folder containing pair subdirectories (required unless TARGET_DIRECTORY is set inside the script)
  --summary, -s      Print a summary of classification counts after analysis
  --examples         Show usage examples and exit

Examples:
  python divide_edit.py --dir ./pairs
  python divide_edit.py --dir ./pairs --summary

Behavior:
- The script prints a classification line for each pair encountered.
- If files cannot be read due to encoding, the script attempts a latin-1 fallback.
- If `--summary` is provided, the script prints counts for each classification after processing.

Usage — divide_sm.py

This script normalizes C files using `clang-format` and classifies changes into four categories:
  - `single`  : A single small hunk (≤ SMALL_BLOCK_MAX_LINES changed lines after normalization).
  - `multi`   : Multiple hunks or a large change block.
  - `comment` : Changes only in comments or whitespace.
  - `none`    : No difference after normalization (or originally identical).

CLI options:
  --dir, -d <path>    Path to directory containing paired files (required)
  --small <N>         Set the small-block threshold N (default is 2)
  --dry-run           Print moves without performing them
  --summary           Print a summary of classification counts after processing
  --examples          Show usage examples and exit

Examples:
  python divide_sm.py --dir ./pairs
  python divide_sm.py --dir ./pairs --small 3 --summary
  python divide_sm.py --dir ./pairs --dry-run

Behavior and outputs:
- The script requires `clang-format` to be installed. It will exit with an error message if `clang-format` is not found.
- For each base pair (files named `<base>_injected.c` and `<base>_fixed.c`), the script classifies the change and moves both files into a subfolder under the input directory:
    - `single_line_changes/`
    - `multi_line_changes/`
    - `comment_only_changes/`
    - `no_changes/`
- In `--dry-run` mode the script only prints intended moves without modifying files.
- The script prints processing progress and returns a dict of statistics (printed after processing).

Notes and recommendations

- Backup your data before running `divide_sm.py` because files will be moved.
- If you do not have `clang-format` installed, you can still run `divide_edit.py` (it does not require clang-format) for a lightweight classification based on raw diffs.
- `divide_sm.py` is intended to filter out purely stylistic or formatting differences by relying on `clang-format` normalization; ensure you use a consistent `clang-format` version if you want reproducible classification results.

Contact and License

- For questions, consult the repository-level README or the included paper PDF for author contacts.
- Code in this folder is distributed under the MIT License (see top-level `LICENSE`).