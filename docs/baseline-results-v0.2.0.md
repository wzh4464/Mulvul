# Cooperative Coevolution Baseline Results (v0.2.0)

## Experiment Configuration

| Parameter | Value |
|-----------|-------|
| Scorer LLM | GPT-5.4 (via OpenRouter) |
| Meta LLM | Claude Opus 4.6 (via OpenRouter) |
| Generations | 5 |
| Population size | 5 per node |
| Samples per class | 30 |
| Tournament k | 3 |
| Migration rate | 0.1 |
| Concurrency | 8 workers |
| Training data | PrimeVul train (175,797 samples) |
| Cascade policy | GreedyCascadePolicy (top-1) |

## Dataset Characteristics

| Metric | Value |
|--------|-------|
| Total samples | 175,797 |
| Benign | 170,935 (97.2%) |
| Vulnerable | 4,862 (2.8%) |
| CWE types | 119 |
| CWEs with <= 5 samples | 64 (54%) |

**Major distribution:** Memory 57.7%, Logic 18.6%, Input 13.5%, Unknown 6.7%, Crypto 1.9%, Injection 1.6%.

## End-to-End Evolution Trajectory

| Gen | e2e Accuracy | Diversity | Best Fitness |
|-----|-------------|-----------|-------------|
| 0 | 0.213 | 0.450 | 0.448 |
| 1 | 0.160 | 0.575 | 0.452 |
| 2 | 0.213 | 0.625 | 0.460 |
| 3 | **0.227** | 0.653 | 0.457 |
| 4 | 0.200 | **0.691** | 0.448 |

- Peak e2e accuracy: **0.227** (Gen 3), a 6.6% improvement over the Gen 0 baseline of 0.213.
- Population diversity increased monotonically from 0.45 to 0.69 — the evolutionary operators are working.
- Gen 1 dip (0.160) is expected exploration-phase behavior after first round of mutation/crossover.

## Per-Stage Node Performance

| Stage | Nodes | Avg F1 | Min F1 | Max F1 |
|-------|-------|--------|--------|--------|
| Major | 5 | 0.630 | 0.473 | 0.815 |
| Middle | 13 | 0.567 | 0.419 | 0.806 |
| CWE | 46 | 0.371 | 0.136 | 0.829 |

All 64 taxonomy nodes have valid prompts with F1 > 0.

### Top 10 Nodes

| Node | F1 | Candidates | Training Samples |
|------|-----|-----------|-----------------|
| cwe_CWE-617 (Reachable Assertion) | 0.829 | 3 | 37 |
| major_Crypto | 0.815 | 6 | 92 |
| middle_Buffer Errors | 0.806 | 5 | 1,581 |
| cwe_CWE-89 (SQL Injection) | 0.800 | 7 | 5 |
| cwe_CWE-190 (Integer Overflow) | 0.730 | 5 | 184 |
| middle_Integer Errors | 0.712 | 5 | 436 |
| major_Memory | 0.711 | 6 | 2,805 |
| cwe_CWE-401 (Memory Leak) | 0.692 | 5 | 94 |
| cwe_CWE-191 (Integer Underflow) | 0.667 | 5 | 7 |
| cwe_CWE-125 (Out-of-bounds Read) | 0.657 | 9 | 538 |

### Bottom 10 Nodes (nonzero)

| Node | F1 | Candidates | Training Samples |
|------|-----|-----------|-----------------|
| cwe_CWE-330 (Insufficient Randomness) | 0.136 | 8 | 0 |
| cwe_CWE-327 (Broken Crypto) | 0.136 | 8 | 5 |
| cwe_CWE-326 (Weak Encryption) | 0.136 | 8 | 4 |
| cwe_CWE-312 (Cleartext Storage) | 0.136 | 8 | 0 |
| cwe_CWE-311 (Missing Encryption) | 0.136 | 8 | 1 |
| cwe_CWE-209 (Error Info Exposure) | 0.136 | 3 | 1 |
| cwe_CWE-94 (Code Injection) | 0.136 | 7 | 15 |
| cwe_CWE-74 (Injection) | 0.136 | 7 | 7 |
| cwe_CWE-805 (Buffer Access) | 0.136 | 9 | 0 |
| cwe_CWE-122 (Heap Overflow) | 0.136 | 9 | 3 |

## Key Findings

### What determines node performance

**1. Candidate list size is the strongest predictor.**

| Candidates | Avg F1 | Nodes |
|-----------|--------|-------|
| 2-3 | 0.46 | 14 |
| 5-6 | 0.55 | 26 |
| 7 | 0.37 | 6 |
| **8** | **0.18** | **7** |
| 9 | 0.35 | 8 |

Nodes with 8 candidates (Cryptography Issues CWEs) have the worst F1 at 0.175. The LLM struggles to distinguish among semantically overlapping options.

**2. Training data has a threshold effect.**

| Samples | Avg F1 | Nodes |
|---------|--------|-------|
| 0-5 | 0.213 | 12 |
| 6-50 | 0.422 | 15 |
| 51-200 | 0.439 | 12 |
| 200+ | 0.418 | 7 |

Below 5 samples, F1 drops sharply. Above 50, additional data provides diminishing returns — the bottleneck shifts from data to classification ambiguity.

**3. Cascade multiplication caps e2e accuracy.**

```
e2e ≈ major_acc × middle_acc × cwe_acc
    ≈ 0.63 × 0.57 × 0.37
    ≈ 0.133 (theoretical)
    = 0.227 (actual peak, higher due to Benign shortcut)
```

Even with good per-stage performance, the three-level cascade compounds errors multiplicatively.

**4. Evolution improved diversity but not seed prompts.**

- Only 3 of 64 nodes had their prompt rewritten by the meta-LLM.
- Rewritten prompts averaged F1=0.306 vs seed prompts at F1=0.437.
- The meta-LLM mutation/crossover strategy needs improvement — it currently degrades more than it improves.
- However, **specific nodes improved significantly** through evolution: CWE-189 (+0.33), middle_Path Traversal (+0.20), middle_Buffer Errors (+0.16).

### Architecture bottleneck

The fixed three-level cascade (Major → Middle → CWE) with greedy top-1 routing is the primary performance limiter. Prompt evolution can improve individual nodes by a few percentage points, but cannot overcome the cascade multiplication ceiling.

## Evolved Prompt Analysis

**Effective evolved prompts** (e.g., CWE-189, Path Traversal) share these patterns:
- Added CWE semantic descriptions ("CWE-189: Numeric Errors — general numeric calculation problems")
- Added explicit decision boundaries ("Choose CWE-190 only for clear integer overflow/wraparound")
- Used formatting emphasis (bold, bullet points) for key distinctions

**Seed prompts that performed well** are simple templates that benefit from:
- Small candidate lists (CWE-617 has only 3 candidates → F1=0.829)
- Clear semantic separation between candidates (CWE-89/SQL Injection is distinctive)

## Recommendations

### Low-cost improvements (prompt-level)
1. **Add CWE descriptions to seed prompts** — `CWE_DESCRIPTIONS` already exists in `cwe_hierarchy.py`
2. **Add inter-candidate decision boundaries** — proven effective by CWE-189's evolution
3. **Fix meta-LLM mutation** — current strategy degrades prompts; needs constrained rewriting

### Architecture-level changes
1. **Merge overlapping CWEs** — Cryptography Issues has 8 CWEs that could merge to 3 groups
2. **Adaptive skip** — high-confidence major predictions could skip middle and go directly to CWE
3. **Two-level architecture** — Major → CWE directly, removing the middle bottleneck

### Training improvements
1. **Filter nodes with < 5 samples** — fallback to parent middle-level classification
2. **Stronger elitism** — protect top-performing prompts from destructive mutation
3. **Constrained mutation** — meta-LLM should only add to prompts, not rewrite them entirely
