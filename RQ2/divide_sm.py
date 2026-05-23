#!/usr/bin/env python3
# classify_and_move_changes_v2.py (modified 2025-06-16)
"""
Iterates through a directory to classify file pairs named <commit>_{fixed|injected}.c.
Before classification, it standardizes the code using clang-format to ignore purely stylistic changes.

Classification Criteria:
  • single_line_changes   —— After normalization, changes are in a single hunk with total changed lines ≤ SMALL_BLOCK_MAX_LINES
  • multi_line_changes    —— All other code changes
  • comment_only_changes  —— Changes involving only comments or whitespace
  • no_changes            —— No difference in original content or after normalization
"""

import os
import shutil
import difflib
import subprocess
from typing import List, Dict, Tuple

# ---------- Parameters ----------
# Line count threshold for a "small code block". After normalization, a single hunk with total changed lines within this limit is considered "single"
SMALL_BLOCK_MAX_LINES = 2
TARGET_EXT = ".c"
# ---------------------------

def normalize_code(file_path: str) -> str:
    """Formats a C code file using clang-format and returns its content."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # The existence of clang-format is checked by shutil.which at the start of the script, so we call it directly here.
    result = subprocess.run(
        ['clang-format', file_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8',
        errors='ignore'
    )
    if result.returncode != 0:
        raise RuntimeError(f"clang-format execution failed on {os.path.basename(file_path)}:\n{result.stderr}")
    return result.stdout

def is_comment_or_empty(line: str) -> bool:
    """Checks if a line contains only comments or whitespace."""
    stripped = line.strip()
    return not stripped or \
           stripped.startswith('//') or \
           (stripped.startswith('/*') and stripped.endswith('*/'))

def parse_raw_diff(diff: List[str]) -> Tuple[bool, bool]:
    """
    Parses the raw diff to quickly determine if there are "no changes" or "only comment/whitespace changes".
    Returns: (is_empty_diff, is_comment_only)
    """
    change_lines = [line[1:] for line in diff if line.startswith(('+', '-')) and not line.startswith(('+++', '---'))]
    if not change_lines:
        return (True, False)  # No changes
    
    is_comment_only = all(is_comment_or_empty(line) for line in change_lines)
    return (False, is_comment_only)

def get_normalized_hunks_info(diff: List[str]) -> List[int]:
    """Extracts the total number of changed lines (+ and -) for each hunk from the unified_diff output."""
    hunks = []
    current_hunk_changes = 0
    in_hunk = False
    for line in diff:
        if line.startswith('@@'):
            if in_hunk:
                hunks.append(current_hunk_changes)
            current_hunk_changes = 0
            in_hunk = True
        elif (line.startswith('+') or line.startswith('-')) and not line.startswith(('+++', '---')):
            current_hunk_changes += 1
    if in_hunk:
        hunks.append(current_hunk_changes)
    return hunks

def classify_change(inj_path: str, fix_path: str) -> str:
    """
    Comprehensively classifies the change type of a file pair.
    Returns: "none" / "comment" / "single" / "multi"
    """
    # 1. Quick check: Determine "no change" or "comment only" based on the raw file diff.
    with open(inj_path, encoding="utf-8", errors="ignore") as f1, \
         open(fix_path, encoding="utf-8", errors="ignore") as f2:
        inj_lines, fix_lines = f1.readlines(), f2.readlines()

    raw_diff = list(difflib.unified_diff(inj_lines, fix_lines, lineterm=''))
    is_empty, is_comment = parse_raw_diff(raw_diff)
    
    if is_empty:
        return "none"
    if is_comment:
        return "comment"

    # 2. Precise classification: Determine single/multi based on the diff after clang-format normalization.
    # (RuntimeError here will be caught by the calling function)
    norm_inj_str = normalize_code(inj_path)
    norm_fix_str = normalize_code(fix_path)

    if norm_inj_str == norm_fix_str:
        # If code is the same after formatting, the original difference was only stylistic 
        # (pure comment changes already excluded by is_comment).
        return "none"

    norm_diff = list(difflib.unified_diff(
        norm_inj_str.splitlines(),
        norm_fix_str.splitlines(),
        lineterm=''
    ))
    
    hunks_info = get_normalized_hunks_info(norm_diff)

    # 3. Apply classification rules
    # If there is only one change hunk and its line count is small, classify as single.
    if len(hunks_info) == 1 and hunks_info[0] <= SMALL_BLOCK_MAX_LINES:
        return "single"
    
    # Otherwise, classify as multi.
    return "multi"

def classify_and_move_changes(directory: str):
    """Main function to iterate through the directory, classify file pairs, and move them."""
    if not os.path.isdir(directory):
        print(f"[!] Directory not found: {directory}")
        return

    dst_folders = {
        "single": "single_line_changes",
        "multi": "multi_line_changes",
        "comment": "comment_only_changes",
        "none": "no_changes"
    }
    for folder_name in dst_folders.values():
        os.makedirs(os.path.join(directory, folder_name), exist_ok=True)

    stats = {k: 0 for k in list(dst_folders.keys()) + ["processed", "error", "skipped"]}
    
    all_files = {f for f in os.listdir(directory) if f.endswith(TARGET_EXT)}
    processed_bases = set()

    for inj_file in sorted(all_files):
        if not inj_file.endswith(f"_injected{TARGET_EXT}"):
            continue
        
        base_name = inj_file[:-len(f"_injected{TARGET_EXT}")]
        fix_file = f"{base_name}_fixed{TARGET_EXT}"

        if base_name in processed_bases:
            continue
        
        if fix_file not in all_files:
            stats["skipped"] += 1
            print(f"[!] Missing pair file: {fix_file} for {inj_file}")
            continue

        processed_bases.add(base_name)
        stats["processed"] += 1
        
        inj_path = os.path.join(directory, inj_file)
        fix_path = os.path.join(directory, fix_file)

        try:
            category = classify_change(inj_path, fix_path)
            stats[category] += 1
            
            # Move the files
            dst_dir = os.path.join(directory, dst_folders[category])
            shutil.move(inj_path, os.path.join(dst_dir, inj_file))
            shutil.move(fix_path, os.path.join(dst_dir, fix_file))
            print(f"✔ {base_name} → {category}")

        except (RuntimeError, FileNotFoundError) as e:
            stats["error"] += 1
            print(f"[ERR] Error processing {base_name}: {e}")
        except Exception as e:
            stats["error"] += 1
            print(f"[FATAL] An unexpected error occurred on {base_name}: {e}")

    return stats

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Classify paired C files (<base>_injected.c and <base>_fixed.c) into change categories and move them into subfolders.",
        epilog="Example: python divide_sm.py --dir ./pairs --small 2 --summary"
    )
    parser.add_argument('--dir', '-d', dest='target_dir', default=None,
                        help='Path to directory containing paired files (required)')
    parser.add_argument('--small', type=int, default=SMALL_BLOCK_MAX_LINES,
                        help=f'Small block threshold in changed lines (default: {SMALL_BLOCK_MAX_LINES})')
    parser.add_argument('--dry-run', action='store_true', help='Do not move files; only print intended actions')
    parser.add_argument('--summary', action='store_true', help='Print a summary of classification counts after processing')
    parser.add_argument('--examples', action='store_true', help='Show usage examples and exit')

    args = parser.parse_args()

    if args.examples:
        print("Examples:\n\n1) Classify and move files in './pairs':\n   python divide_sm.py --dir ./pairs\n\n2) Use a different small-block threshold and show summary:\n   python divide_sm.py --dir ./pairs --small 3 --summary\n\n3) Dry-run to preview moves without changing files:\n   python divide_sm.py --dir ./pairs --dry-run")
        exit(0)

    # Pre-execution Check: clang-format must be present
    if shutil.which("clang-format") is None:
        print("\n[!!!] Critical Error: 'clang-format' not found.")
        print("Please install clang-format and ensure it is in your system's PATH environment variable.")
        exit(1)

    if not args.target_dir:
        print("Error: --dir is required. Use --dir <path> to specify the directory containing the paired files.")
        exit(1)

    target_dir = args.target_dir
    SMALL_BLOCK_MAX_LINES = args.small

    print(f"Directory: {target_dir}\nFiles will be moved based on clang-format standardization. Please ensure you have a backup.")

    # Support dry-run by temporarily overriding shutil.move
    original_move = shutil.move
    if args.dry_run:
        def _dry_move(src, dst):
            print(f"[DRY-RUN] would move: {src} -> {dst}")
        shutil.move = _dry_move

    res = classify_and_move_changes(target_dir)

    # Restore shutil.move if overridden
    if args.dry_run:
        shutil.move = original_move

    if res:
        print("\n=== Processing Complete ===")
        print("-" * 25)
        for key, value in res.items():
            if value > 0:
                print(f"{key:<12}: {value}")
        print("-" * 25)

    if args.summary and res:
        print("\nSummary details:")
        for k, v in res.items():
            print(f"  {k}: {v}")