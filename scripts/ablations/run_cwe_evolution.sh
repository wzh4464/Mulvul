#!/usr/bin/env bash
set -euo pipefail

DEV=${1:-"/workspace/data/cwe/primevul_mapped/balanced/balanced_valid.jsonl"}
TEST=${2:-"/workspace/data/cwe/primevul_mapped/balanced/balanced_test.jsonl"}
OUT=${3:-"/workspace/outputs/cwe_results"}
ALG=${4:-"de"}
POP=${5:-10}
GEN=${6:-5}
LLM=${7:-"gpt-3.5-turbo"}

uv run python /workspace/scripts/ablations/run_cwe_evolution.py \
  --dev_file "$DEV" \
  --test_file "$TEST" \
  --output_dir "$OUT" \
  --algorithm "$ALG" \
  --population_size "$POP" \
  --generations "$GEN" \
  --llm_type "$LLM"