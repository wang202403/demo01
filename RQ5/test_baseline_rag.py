#!/usr/bin/env python3
# locate_vuln_lines_rag_final_simplified.py

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import requests
from requests.exceptions import ReadTimeout, RequestException

try:
    from rank_bm25 import BM25Okapi
except ImportError:
    raise SystemExit("pip install rank-bm25")


OLLAMA_ANALYSIS_URL = "http://localhost:8081/v1/chat/completions"
MAX_EXAMPLE_FUNC_CHARS = 4000 
TEMPERATURE = 0.0
REQ_K = 10
MIN_PROB = 0.01
TIMEOUT = 300 
RETRIES = 1
BACKOFF_SEC = 5
MODEL_CONTEXT_WINDOWS = {"llama3": 8192, "codellama": 16384, "deepseek-coder": 16384, "qwen": 32768, "qwen2.5": 32768}
CHARS_PER_TOKEN = 3.5
CONTEXT_SAFETY_MARGIN = 500


def get_exclude_prefix(model_name: str) -> Optional[str]:
    name_lower = model_name.lower(); mapping = {"llama3": "llama", "codellama": "collama", "deepseek-coder": "dsc", "qwen": "qwen"}
    for key, prefix in mapping.items():
        if key in name_lower: return prefix
    if "deepseek-r" in name_lower: return "dsr"
    return None

def load_knowledge_base(data_dir: str, exclude_prefix: Optional[str]) -> Dict[str, List[Dict]]:
    kb: Dict[str, List[Dict]] = {"single": [], "multi": []}; data_path = Path(data_dir)
    if not data_path.is_dir(): print(f"no rag data"); return kb
    files_to_process = [f for f in data_path.glob("*.jsonl") if not (exclude_prefix and f.name.startswith(exclude_prefix))]
    print(f"loading")
    for file_path in files_to_process:
        target_list = None
        if file_path.name.endswith("_single.jsonl"): target_list = kb["single"]
        elif file_path.name.endswith("_multi.jsonl"): target_list = kb["multi"]
        else: continue
        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if "func" in entry and "vulc" in entry: target_list.append(entry)
                except (json.JSONDecodeError, KeyError): continue
    print(f"load complete")
    return kb

class BM25Retriever:
    def __init__(self, knowledge_base: Dict[str, List[Dict]]):
        self.docs = {"single": knowledge_base.get("single", []), "multi": knowledge_base.get("multi", [])}
        self.indices: Dict[str, Optional[BM25Okapi]] = {"single": None, "multi": None}
        for rag_type in self.docs:
            docs_list = self.docs[rag_type]
            if docs_list:
                print(f"running")
                # BM25 index should be built on raw code ('func' field)
                tokenized_corpus = [doc["func"].split() for doc in docs_list]; self.indices[rag_type] = BM25Okapi(tokenized_corpus)
    def retrieve(self, target_code: str, k: int, rag_type: str) -> List[Dict]:
        bm25_index = self.indices.get(rag_type); doc_list = self.docs.get(rag_type, [])
        if not bm25_index or not doc_list: return []
        tokenized_query = target_code.split(); return bm25_index.get_top_n(tokenized_query, doc_list, n=k)


def _call_ollama_api(url: str, model: str, prompt: str, num_ctx: int) -> Optional[str]:
    payload = {"model": model, "temperature": TEMPERATURE, "stream": False, "options": {"num_ctx": num_ctx, "temperature": 0.0}, "messages": [{"role": "user", "content": prompt}]}
    try:
        resp = requests.post(url, json=payload, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except ReadTimeout:
        print(f"TIMEOUT")
    except RequestException as exc:
        print(f"Failed")
    return None

def _add_line_numbers(code: str) -> str:
    """Adds line numbers to a string of code, starting from 1."""
    lines = code.split('\n')
    return '\n'.join(f"{i+1}: {line}" for i, line in enumerate(lines))

def create_rag_prompt(code: str, examples: List[Dict]) -> str:
    """
    Creates the main prompt for vulnerability localization.
    Assumes the input `code` (target code) already has line numbers.
    """
    prompt_parts = [
        "You are an expert on vulnerability localization (identifying the code lines that are vulnerable from a given code sample). There are a few examples to demonstrate this task:",
        ""
    ]

    for i, ex in enumerate(examples, 1):
        # Add line numbers to the example code from the knowledge base
        code_with_lines = _add_line_numbers(ex['func'])
        if len(code_with_lines) > MAX_EXAMPLE_FUNC_CHARS:
             code_with_lines = code_with_lines[:MAX_EXAMPLE_FUNC_CHARS] + "\n... (function truncated) ..."
        
        # Format the vulnerable lines for the answer
        vulnerable_lines = ", ".join(map(str, ex['vulc']))
        answer = f"the vulnerable lines are {vulnerable_lines}"

        prompt_parts.extend([
            f"Exemplar {i}:",
            f"{code_with_lines}",
            f"Answer: {answer}",
            ""
        ])

    # Add the target code section. The input 'code' is already numbered.
    prompt_parts.extend([
        "Now, for the following code, identify the vulnerable code lines along with the probability that each line is vulnerable.",
        "",
        f"{code}", # Use the pre-numbered code directly
        ""
    ])

    # Add the final output instruction, strictly requiring JSON
    prompt_parts.append(
        "Output: each line with the probability it's vulnerable as {code line, probability}; no explanations. "
        "Respond ONLY with a single JSON array of objects, where each object has a 'line' and a 'prob' key. "
        'Example: [{"line": 10, "prob": 0.95}, {"line": 15, "prob": 0.80}]'
    )

    return "\n".join(prompt_parts)

def create_zero_shot_prompt(code: str) -> str:
    """
    Original zero-shot prompt. Assumes input 'code' already has line numbers.
    """
    return (
        "You are a static-analysis assistant.\n"
        f"List the **top-{REQ_K}** most likely vulnerable line numbers with their probabilities in the following C function.\n\n"
        "Respond ONLY with a JSON array of objects, where each object has a 'line' and a 'prob' key. Example: [{\"line\": 23, \"prob\": 0.9}]"
        f"\n\n----- BEGIN C FUNCTION -----\n{code}\n----- END C FUNCTION -----"
    )

def ask_analysis_llm(model_name: str, code_with_lineno: str, examples: List[Dict]) -> Optional[str]:
    """Uses the final LLM for vulnerability analysis."""
    if examples:
        # Pass the pre-numbered code to the prompt creation function
        prompt = create_rag_prompt(code_with_lineno, examples)
        print(f"analyzing...")
    else:
        prompt = create_zero_shot_prompt(code_with_lineno)
        print(f"using zero shot {model_name}...")
    token_limit = MODEL_CONTEXT_WINDOWS.get(next((key for key in model_name if key in MODEL_CONTEXT_WINDOWS), "default"), 8192)
    return _call_ollama_api(OLLAMA_ANALYSIS_URL, model_name, prompt, token_limit)

def parse_predictions(raw: Optional[str]) -> List[Dict[str, Any]]:
    """Robust JSON parser."""
    if not raw: return []
    content = raw
    match = re.search(r"```json\s*(.*?)\s*```", raw, re.S)
    if match: content = match.group(1)
    else:
        first_bracket = content.find('[')
        first_brace = content.find('{')
        if first_bracket != -1 and (first_brace == -1 or first_bracket < first_brace):
            last_bracket = content.rfind(']')
            if last_bracket != -1: content = content[first_bracket:last_bracket+1]
        elif first_brace != -1:
            last_brace = content.rfind('}')
            if last_brace != -1: content = content[first_brace:last_brace+1]

    try:
        data = json.loads(content)
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        print(f"json prase failed")
        return []
        
    preds: List[Dict[str, float]] = []
    if isinstance(data, list) and data:
        for d in data:
            if isinstance(d, dict):
                try: preds.append({"line": int(d["line"]), "prob": float(d.get("prob", 1.0))})
                except (KeyError, ValueError, TypeError): continue
            else: 
                try: preds.append({"line": int(d), "prob": 1.0})
                except (ValueError, TypeError): continue
    
    preds.sort(key=lambda x: x["prob"], reverse=True)
    return preds[:REQ_K]

def evaluate(csv_path: str, model_name: str, limit: Optional[int], rag_k: int, rag_type: Optional[str], data_dir: str) -> None:
    # IMPORTANT: Assumes CSV has 'processed_func' (raw code) and 'code_with_lineno' (numbered code)
    try:
        df = pd.read_csv(csv_path)
        required_cols = {'processed_func', 'code_with_lineno', 'flaw_line_index'}
        if not required_cols.issubset(df.columns):
            missing = required_cols - set(df.columns)
            raise SystemExit(f"please make sure file has'processed_func', 'code_with_lineno', 'flaw_line_index'。")
    except FileNotFoundError:
        raise SystemExit(f"no csv {csv_path}")


    retriever = None
    if rag_k > 0 and rag_type:
        exclude_prefix = get_exclude_prefix(model_name)
        kb = load_knowledge_base(data_dir, exclude_prefix)
        retriever = BM25Retriever(kb)
    else: print("rag disabled")
    
    total, hits1, hits3, hits10, processed_count = 0, 0, 0, 0, 0
    for _, row in df.iterrows():
        if limit is not None and processed_count >= limit: break
        
        # Use raw code for retrieval, and pre-numbered code for the prompt
        raw_code = row["processed_func"]
        code_with_lineno = row["code_with_lineno"]
        flaw_line_idx = int(row["flaw_line_index"])
        
        final_examples = []
        if retriever and rag_k > 0 and rag_type:
            # Use raw_code for BM25 retrieval for better matching
            final_examples = retriever.retrieve(raw_code, k=rag_k, rag_type=rag_type)
            print(f"complete")

        # Use code_with_lineno for the final analysis prompt
        pred_raw = ask_analysis_llm(model_name, code_with_lineno, final_examples)
        pred_ls = [p["line"] for p in parse_predictions(pred_raw)]

        if pred_ls:
            if flaw_line_idx == pred_ls[0]: hits1 += 1
            if flaw_line_idx in pred_ls[:3]: hits3 += 1
            if flaw_line_idx in pred_ls: hits10 += 1
        
        processed_count += 1; total = processed_count
        if total > 0 and total % 10 == 0: print(f"progress {total} func | Top-1 {hits1/total:.2%} · Top-3 {hits3/total:.2%} · Top-10 {hits10/total:.2%}")

    if total == 0: print("no record"); return
    
    print("\n==========  res  ==========")
    print(f"model           : {model_name}")
    rag_mode = f"using (BM25 k={rag_k})" if rag_k > 0 else "disabled"
    print(f"RAG       : {rag_mode}")
    if rag_k > 0 and rag_type: print(f"RAG type   : {rag_type}")
    print(f"total         : {total}")
    print(f"Top-1 hits   : {hits1/total:.3%} ({hits1})")
    print(f"Top-3 hits   : {hits3/total:.3%} ({hits3})")
    print(f"Top-10 hits  : {hits10/total:.3%} ({hits10})")

if __name__ == "__main__":
    MODELS_TO_TEST = ["deepseek-r1:70b"]
    # MODELS_TO_TEST = ["llama3:70b", "codellama:34b-instruct", "deepseek-coder:33b-instruct", "qwen2.5:32b-instruct"]
    if not shutil.which("ollama"): print("error")

    ap = argparse.ArgumentParser(description="rag", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("csv", nargs="?", default="vul_trig_func_loc_with_lineno.csv")
    ap.add_argument("-n", "--limit", type=int)
    ap.add_argument("--rag-k", type=int, default=3)
    ap.add_argument("--rag-type", type=str, default=None, choices=["single", "multi"])
    ap.add_argument("--data-dir", type=str, default="./data")
    args = ap.parse_args()

    types_to_evaluate = [None] if args.rag_k == 0 else [args.rag_type] if args.rag_type else ["single", "multi"]
    for rag_type_to_test in types_to_evaluate:
        for model_to_test in MODELS_TO_TEST:
            print("\n" + "="*35)
            rag_type_str = f"RAG: {rag_type_to_test}" if rag_type_to_test else "RAG no"
            print(f"  starting: {model_to_test} ({rag_type_str})")
            print("="*35 + "\n")
            
            evaluate(
                csv_path=args.csv, model_name=model_to_test, limit=args.limit,
                rag_k=args.rag_k, rag_type=rag_type_to_test, data_dir=args.data_dir
            )
            print(f"\n[done] model {model_to_test} ({rag_type_str}) ended")
    print("\all done")
    