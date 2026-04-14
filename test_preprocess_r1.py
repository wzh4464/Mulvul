#!/usr/bin/env python3
"""Test R1 prompt with code preprocessing to see if it beats plain R1 (81.2%)."""
import sys
sys.path.insert(0, '.')
import json, os
from pathlib import Path
from major_evolution import PROMPTS, build_major_dataset, evaluate

# Load raw data
RAW_DATA = "/Users/zihanwu/Public/codes/Mulvul/data/enter/cwd_benchmark_2.json"
with open(RAW_DATA) as f:
    raw_data = json.load(f)

dataset = build_major_dataset("Memory", raw_data)
r1_prompt = PROMPTS["Memory"][1]

print(f"Dataset: {len(dataset)} samples")
print(f"Running R1 + preprocess...")

metrics = evaluate(dataset, r1_prompt, major="Memory", verbose=True, preprocess=True)

print(f"\n=== R1 + preprocess: accuracy={metrics['accuracy']:.1%}  FP={metrics['fp_count']}  FN={metrics['fn_count']} ===")

# Save result
out = {
    "round": "1+preprocess",
    "major": "Memory",
    "accuracy": metrics["accuracy"],
    "correct": metrics["correct"],
    "total": metrics["total"],
    "fp_count": metrics["fp_count"],
    "fn_count": metrics["fn_count"],
    "fp_samples": metrics["fp_samples"],
    "fn_samples": metrics["fn_samples"],
}
with open("major_evolution_results/Memory/round1_preprocess.json", "w") as f:
    json.dump(out, f, ensure_ascii=False, indent=2)
print("Saved to major_evolution_results/Memory/round1_preprocess.json")
