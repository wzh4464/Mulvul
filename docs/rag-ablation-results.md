# RAG Ablation Study Results

## Configuration

| Parameter | Baseline | RAG |
|-----------|----------|-----|
| Eval data | PrimeVul valid (balanced 200 samples) |
| Prompts | `prompt_artifact.json` from v0.2.0 coevolution |
| Scorer LLM | GPT-5.4 (OpenRouter) |
| Cascade policy | GreedyCascadePolicy (top-1) |
| Knowledge base | - | 429 samples (5 per CWE, hierarchical) |
| `--ablation rag` | No | Yes |

## Results

### End-to-End Accuracy

| Level | Baseline | RAG | Absolute | Relative |
|-------|----------|-----|----------|----------|
| Binary | 68.0% | **69.0%** | +1.0% | +1.5% |
| Major | 47.5% | **54.5%** | +7.0% | **+14.7%** |
| Middle | 12.8% | **15.1%** | +2.3% | **+18.2%** |
| CWE | 4.7% | **7.0%** | +2.3% | **+50.0%** |

RAG improves all levels. The relative improvement increases at finer granularity: Binary +1.5%, Major +14.7%, Middle +18.2%, CWE +50.0%.

### Per-Major Breakdown

| Major | n | Baseline | RAG | Delta |
|-------|---|----------|-----|-------|
| Benign | 114 | 51.8% | **63.2%** | +11.4% |
| Injection | 3 | 33.3% | **100.0%** | +66.7% |
| Input | 11 | 27.3% | **45.5%** | +18.2% |
| Logic | 16 | 25.0% | 25.0% | 0.0% |
| Memory | 54 | **50.0%** | 44.4% | -5.6% |
| Crypto | 2 | 50.0% | 50.0% | 0.0% |

### Analysis

**Where RAG helps most:**
- **Benign classification** (+11.4%): Retrieved vulnerability examples provide contrast that helps the LLM identify code that *doesn't* match known vulnerability patterns.
- **Rare categories** (Injection +66.7%, Input +18.2%): Categories with few training samples benefit most from retrieved evidence — the KB provides concrete examples the seed prompts lack.
- **CWE-level discrimination** (+50% relative): Fine-grained CWE classification is where evidence-based reasoning adds the most value.

**Where RAG hurts:**
- **Memory** (-5.6%): The dominant category with the most training data. Retrieved similar code may be *too* similar across Buffer Errors / Memory Management / Pointer Dereference subcategories, introducing confusion at the middle level.

**Why Middle/CWE absolute numbers are low:**
The cascade multiplication effect remains the bottleneck. Even with RAG, Major accuracy at 54.5% means ~45% of samples are already misrouted before reaching Middle/CWE. The RAG improvement is real but stacks on top of the cascade ceiling.

## Knowledge Base Construction

Built from PrimeVul training data:
- Up to 5 representative samples per CWE (random, seed=42)
- Hierarchically indexed: by_major, by_middle, by_cwe
- Total: 429 samples across 119 CWEs, 13 middle categories, 5 major categories
- Code truncated to 2000 chars, descriptions to 200 chars

## Reproduction

```bash
# Build KB (one-time)
python scripts/build_knowledge_base.py \
  --train-file data/primevul/primevul/primevul_train.jsonl \
  --output data/primevul/knowledge_base.json

# Baseline
uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/primevul/primevul_valid.jsonl \
  --prompts-path outputs/mainline/evolution/prompt_artifact.json \
  --output-dir outputs/mainline/eval_baseline \
  --max-samples 200 --balanced

# RAG ablation
uv run python scripts/run_mainline_evaluation.py \
  --eval-file data/primevul/primevul/primevul_valid.jsonl \
  --prompts-path outputs/mainline/evolution/prompt_artifact.json \
  --output-dir outputs/mainline/eval_rag \
  --max-samples 200 --balanced \
  --kb-path data/primevul/knowledge_base.json \
  --ablation rag
```
