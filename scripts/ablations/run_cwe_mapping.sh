#!/usr/bin/env bash
set -euo pipefail

INPUT=${1:-"/workspace/data/primevul/dev.jsonl"}
OUTDIR=${2:-"/workspace/data/cwe/primevul_mapped"}
SAMPLES=${3:-1000}

uv run python /workspace/cwe_extension/cwe_mapping.py \
  --input "$INPUT" \
  --output_dir "$OUTDIR" \
  --samples_per_category "$SAMPLES"