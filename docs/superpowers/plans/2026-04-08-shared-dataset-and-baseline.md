# Shared Dataset & Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build PrimeVul-Balanced-20 subset and run baseline experiment for ablation comparisons.

**Architecture:** Script filters PrimeVul train to 20 CWEs (>= 50 samples each), caps each at 50 samples + 1000 benign. Baseline runs current CoevolutionaryTrainer on this subset for 5 generations.

**Tech Stack:** Python 3.9+, `uv run`, existing `CoevolutionaryTrainer`

---

## File Structure

| File | Responsibility |
|---|---|
| `scripts/build_balanced_subset.py` | **Create.** Build PrimeVul-Balanced-20 from full training data |
| `data/primevul/primevul_balanced_20.jsonl` | **Output.** The balanced subset |
| `outputs/ablation_baseline/` | **Output.** Baseline evolution results |

---

### Task 1: Build PrimeVul-Balanced-20 Dataset

**Files:**
- Create: `scripts/build_balanced_subset.py`
- Output: `data/primevul/primevul_balanced_20.jsonl`

- [ ] **Step 1: Write the dataset builder script**

```python
#!/usr/bin/env python3
"""Build PrimeVul-Balanced-20: a small balanced subset for ablation experiments."""

from __future__ import annotations

import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from mulvul.data.cwe_hierarchy import CWE_TO_MIDDLE, MIDDLE_TO_MAJOR

MIN_SAMPLES = 50
SAMPLES_PER_CWE = 50
BENIGN_COUNT = 1000
SEED = 42


def main():
    random.seed(SEED)
    src = Path("data/primevul/primevul/primevul_train.jsonl")

    # Pass 1: group by CWE
    by_cwe: dict[str, list[dict]] = defaultdict(list)
    benign: list[dict] = []

    with src.open() as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            if int(item.get("target", 0)) == 0:
                benign.append(item)
            else:
                cwes = item.get("cwe", [])
                if cwes:
                    by_cwe[cwes[0]].append(item)

    # Filter to CWEs with >= MIN_SAMPLES
    eligible = {cwe: samples for cwe, samples in by_cwe.items() if len(samples) >= MIN_SAMPLES}
    print(f"Eligible CWEs (>= {MIN_SAMPLES} samples): {len(eligible)}")

    # Sample
    selected: list[dict] = []
    for cwe in sorted(eligible.keys()):
        pool = eligible[cwe]
        n = min(SAMPLES_PER_CWE, len(pool))
        selected.extend(random.sample(pool, n))
        mid = CWE_TO_MIDDLE.get(cwe, "Unknown")
        maj = MIDDLE_TO_MAJOR.get(mid, "Unknown")
        print(f"  {maj} > {mid} > {cwe}: {n} samples")

    # Add benign
    benign_sample = random.sample(benign, min(BENIGN_COUNT, len(benign)))
    selected.extend(benign_sample)
    random.shuffle(selected)

    # Write
    out = Path("data/primevul/primevul_balanced_20.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as f:
        for item in selected:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")

    vul = len(selected) - len(benign_sample)
    print(f"\nWritten {len(selected)} samples ({vul} vulnerable + {len(benign_sample)} benign) to {out}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the builder**

```bash
uv run python scripts/build_balanced_subset.py
```

Expected: Creates `data/primevul/primevul_balanced_20.jsonl` with ~2000 samples.

- [ ] **Step 3: Verify the dataset**

```bash
wc -l data/primevul/primevul_balanced_20.jsonl
uv run python -c "
import json
from collections import Counter
lines = open('data/primevul/primevul_balanced_20.jsonl').readlines()
targets = Counter(int(json.loads(l)['target']) for l in lines)
print(f'Total: {len(lines)}, Benign: {targets[0]}, Vulnerable: {targets[1]}')
cwes = Counter(json.loads(l)['cwe'][0] for l in lines if int(json.loads(l)['target'])==1)
print(f'CWE types: {len(cwes)}')
for c, n in cwes.most_common(): print(f'  {c}: {n}')
"
```

- [ ] **Step 4: Commit**

```bash
git add scripts/build_balanced_subset.py data/primevul/primevul_balanced_20.jsonl
git commit -m "feat: add PrimeVul-Balanced-20 subset for ablation experiments"
```

---

### Task 2: Run Baseline Experiment

- [ ] **Step 1: Run baseline evolution on the balanced subset**

```bash
uv run python scripts/run_mainline_evolution.py \
  --train-file data/primevul/primevul_balanced_20.jsonl \
  --output-dir outputs/ablation_baseline \
  --rounds 5 \
  --samples-per-class 30
```

- [ ] **Step 2: Record baseline results**

```bash
cat outputs/ablation_baseline/evolution.jsonl | python3 -c "
import json, sys
lines = sys.stdin.readlines()
for l in lines:
    e = json.loads(l)
    if e['event'] in ('cascade_eval_done', 'generation_end'):
        print(json.dumps(e['data'], indent=2))
"
```

Save the output as `outputs/ablation_baseline/README.md` with avg F1 per generation.

- [ ] **Step 3: Commit baseline results**

```bash
git add outputs/ablation_baseline/
git commit -m "data: baseline results on PrimeVul-Balanced-20"
```
