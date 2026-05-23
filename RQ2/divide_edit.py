# -*- coding: utf-8 -*-

import os
import difflib
import argparse

def read_file_lines(file_path):
    """Safely reads a file and returns a list of lines, handling potential encoding errors."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.readlines()
    except UnicodeDecodeError:
        try:
            # Fallback to another common encoding if UTF-8 fails
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.readlines()
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return None

def classify_change_type(vul_file, fixed_file):
    """
    Compares two files and classifies the type of change.

    Returns:
        'add': Only insertions were made.
        'del': Only deletions were made.
        'replace': A mix of insertions and deletions.
        'no change': The files are identical.
        'error': An error occurred during file reading.
    """
    vul_lines = read_file_lines(vul_file)
    fixed_lines = read_file_lines(fixed_file)

    if vul_lines is None or fixed_lines is None:
        return 'error'

    # Use difflib.SequenceMatcher to get the opcodes.
    # SequenceMatcher compares two sequences (in this case, lists of file lines).
    matcher = difflib.SequenceMatcher(None, vul_lines, fixed_lines)
    
    # get_opcodes() returns a list of instructions on how to turn 'a' into 'b'.
    # Each instruction is a tuple: (tag, i1, i2, j1, j2)
    # Possible values for 'tag':
    # 'replace': a[i1:i2] should be replaced by b[j1:j2]
    # 'delete':  a[i1:i2] should be deleted
    # 'insert':  b[j1:j2] should be inserted
    # 'equal':   a[i1:i2] and b[j1:j2] are the same
    opcodes = matcher.get_opcodes()

    has_insertion = False
    has_deletion = False

    for tag, i1, i2, j1, j2 in opcodes:
        if tag == 'replace':
            # A 'replace' operation is fundamentally a deletion followed by an insertion.
            has_deletion = True
            has_insertion = True
        elif tag == 'delete':
            has_deletion = True
        elif tag == 'insert':
            has_insertion = True
    
    # Determine the change type based on the flags.
    if has_insertion and has_deletion:
        return 'replace'
    elif has_insertion:
        return 'add'
    elif has_deletion:
        return 'del'
    else:
        return 'no change'

def analyze_directory(main_folder_path):
    """
    Iterates through all subdirectories in a main folder and classifies each file pair.
    """
    if not os.path.isdir(main_folder_path):
        print(f"Error: Directory '{main_folder_path}' not found.")
        return

    print(f"Starting analysis of directory: {main_folder_path}\n" + "="*40)

    # Iterate over all entries in the main directory
    for pair_folder_name in os.listdir(main_folder_path):
        pair_folder_path = os.path.join(main_folder_path, pair_folder_name)

        # Ensure the entry is a directory
        if os.path.isdir(pair_folder_path):
            vul_file_path = os.path.join(pair_folder_path, 'vul.c')
            fixed_file_path = os.path.join(pair_folder_path, 'fixed.c')

            # Check if both vul.c and fixed.c exist
            if os.path.exists(vul_file_path) and os.path.exists(fixed_file_path):
                change_type = classify_change_type(vul_file_path, fixed_file_path)
                print(f"Pair: {pair_folder_name:<20} -> Classification: {change_type}")
            else:
                print(f"Pair: {pair_folder_name:<20} -> Warning: Missing vul.c or fixed.c file.")
    
    print("="*40 + "\nAnalysis complete.")

def analyze_directory_stats(main_folder_path):
    """Iterates through all subdirectories and classifies each file pair.
    Returns a dict with counts for each classification."""
    counts = {"add":0, "del":0, "replace":0, "no change":0, "error":0, "missing":0}

    if not os.path.isdir(main_folder_path):
        print(f"Error: Directory '{main_folder_path}' not found.")
        return counts

    print(f"Starting analysis of directory: {main_folder_path}\n" + "="*40)

    for pair_folder_name in os.listdir(main_folder_path):
        pair_folder_path = os.path.join(main_folder_path, pair_folder_name)
        if os.path.isdir(pair_folder_path):
            vul_file_path = os.path.join(pair_folder_path, 'vul.c')
            fixed_file_path = os.path.join(pair_folder_path, 'fixed.c')
            if os.path.exists(vul_file_path) and os.path.exists(fixed_file_path):
                change_type = classify_change_type(vul_file_path, fixed_file_path)
                print(f"Pair: {pair_folder_name:<20} -> Classification: {change_type}")
                if change_type in counts:
                    counts[change_type] += 1
                else:
                    counts.setdefault(change_type, 0)
                    counts[change_type] += 1
            else:
                print(f"Pair: {pair_folder_name:<20} -> Warning: Missing vul.c or fixed.c file.")
                counts['missing'] += 1

    print("="*40 + "\nAnalysis complete.")
    return counts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Classify edit types between 'vul.c' and 'fixed.c' files in subfolders of a directory.",
        epilog="Example: python divide_edit.py --dir ./pairs --summary"
    )
    parser.add_argument('--dir', '-d', dest='target_dir', default=None,
                        help='Path to main folder containing pair subdirectories (default: use embedded TARGET_DIRECTORY if present)')
    parser.add_argument('--summary', '-s', action='store_true', help='Print a summary of classification counts after analysis')
    parser.add_argument('--examples', action='store_true', help='Show usage examples and exit')
    args = parser.parse_args()

    if args.examples:
        print("Examples:\n\n1) Analyze a local folder named 'pairs':\n   python divide_edit.py --dir ./pairs\n\n2) Analyze and show a summary of counts:\n   python divide_edit.py --dir ./pairs --summary")
        exit(0)

    # Determine target directory: prefer CLI argument, otherwise fallback to embedded TARGET_DIRECTORY
    target_directory = args.target_dir if args.target_dir else globals().get('TARGET_DIRECTORY', None)
    if not target_directory:
        print("Error: No target directory specified. Use --dir to set the path or edit the TARGET_DIRECTORY in the script.")
        exit(1)

    stats = analyze_directory_stats(target_directory)

    if args.summary:
        print("\nSummary of classifications:")
        for k, v in stats.items():
            print(f"  {k}: {v}")