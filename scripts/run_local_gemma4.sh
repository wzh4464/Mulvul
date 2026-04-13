#!/usr/bin/env bash
# Run full evolution + evaluation with local Gemma 4 on MLX
# Quick validation: 1 round, population=3, 5 samples/class, phase1-only
set -euo pipefail

export API_BASE_URL="http://127.0.0.1:18082/v1"
export API_KEY="local-mlx"
export MODEL_NAME="gemma4-31b-it-8bit-mlx"
export META_API_BASE_URL="http://127.0.0.1:18082/v1"
export META_API_KEY="local-mlx"
export META_MODEL_NAME="gemma4-31b-it-8bit-mlx"
export OPENAI_CLIENT_TIMEOUT=300
export OPENAI_CLIENT_MAX_RETRIES=3
export OPENAI_CLIENT_RETRY_DELAY=5
export ASYNC_LLM_TIMEOUT=300
export ASYNC_LLM_MAX_RETRIES=3
export ASYNC_LLM_RETRY_DELAY=5
export SVEN_LLM_TIMEOUT=300
export SVEN_LLM_MAX_RETRIES=3
export SVEN_LLM_RETRY_DELAY=5
export no_proxy="localhost,127.0.0.1"
export NO_PROXY="localhost,127.0.0.1"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_BASE="./outputs/local_gemma4_quick_${TIMESTAMP}"
TRAIN_FILE="data/primevul/primevul_balanced_20.jsonl"
KB_PATH="data/primevul/knowledge_base.json"

echo "========================================"
echo "  Mulvul Local Gemma 4 Quick Validation"
echo "  Output: ${OUTPUT_BASE}"
echo "  Model:  ${MODEL_NAME}"
echo "  API:    ${API_BASE_URL}"
echo "  Params: 1 round, pop=3, samples=5/class"
echo "========================================"

mkdir -p "${OUTPUT_BASE}/evolution" "${OUTPUT_BASE}/evaluation"

# Phase 1: Evolution (phase1-only for quick validation)
echo ""
echo ">>> Phase 1: Running prompt evolution (1 round, phase1-only)..."
uv run python scripts/run_mainline_evolution.py \
    --train-file "${TRAIN_FILE}" \
    --output-dir "${OUTPUT_BASE}/evolution" \
    --kb-path "${KB_PATH}" \
    --rounds 1 \
    --samples-per-class 5 \
    --max-workers 1 \
    --population-size 3 \
    --phase1-only \
    --elitism-threshold 0.5 \
    2>&1 | tee "${OUTPUT_BASE}/evolution_console.log"

EVOLUTION_PROMPTS="${OUTPUT_BASE}/evolution/prompt_bundle.json"
if [ ! -f "${EVOLUTION_PROMPTS}" ]; then
    echo "ERROR: Evolution did not produce prompt_bundle.json"
    exit 1
fi

echo ""
echo ">>> Phase 2: Running evaluation with evolved prompts..."
uv run python scripts/run_mainline_evaluation.py \
    --eval-file "${TRAIN_FILE}" \
    --prompts-path "${EVOLUTION_PROMPTS}" \
    --output-dir "${OUTPUT_BASE}/evaluation" \
    --kb-path "${KB_PATH}" \
    --max-workers 1 \
    --seed 42 \
    2>&1 | tee "${OUTPUT_BASE}/evaluation_console.log"

echo ""
echo "========================================"
echo "  Complete!"
echo "  Evolution log: ${OUTPUT_BASE}/evolution/evolution.jsonl"
echo "  Eval summary:  ${OUTPUT_BASE}/evaluation/summary.json"
echo "  Eval details:  ${OUTPUT_BASE}/evaluation/evaluation_details.jsonl"
echo "========================================"
