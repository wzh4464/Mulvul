#!/usr/bin/env python3
"""
Cascade accuracy evaluator.

Loads best prompts for each major, then runs ALL major prompts on a unified
test set drawn from the raw benchmark.

For each sample:
  - Run Memory / Injection / Logic / Input prompts concurrently
  - If any prompt predicts VULNERABLE, pick the one with highest confidence
  - If all predict BENIGN, classify as BENIGN

Ground truth:
  - Vulnerable samples: the correct major is given by CWD_TO_MAJOR
  - Benign samples: correct answer is BENIGN

Cascade is correct if:
  - Vulnerable sample: predicted major == actual major
  - Benign sample: all prompts predicted BENIGN (or highest-confidence is BENIGN)

Usage:
    uv run python cascade_eval.py [--per-cwd N] [--out result.json]
"""
import argparse
import asyncio
import json
import os
import random
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from openai import AsyncOpenAI
    HAS_ASYNC_OPENAI = True
except ImportError:
    HAS_ASYNC_OPENAI = False

# ── Config ─────────────────────────────────────────────────────────────────────
SEED = 42
RAW_DATA = "/Users/zihanwu/Public/codes/Mulvul/data/enter/cwd_benchmark_2.json"
RESULTS_DIR = "major_evolution_results"
CODE_LIMIT = 8000
CONCURRENCY = 10
MAX_TOKENS = 600

# ── Best rounds (update as experiments progress) ───────────────────────────────
BEST_ROUNDS: Dict[str, int] = {
    "Memory":    1,
    "Injection": 2,
    "Logic":     1,
    "Input":     2,
}

BINARY_BEST_ROUND = 7   # Best binary round from binary_evolution_results/

# ── CWD-to-Major mapping ───────────────────────────────────────────────────────
CWD_TO_MAJOR: Dict[str, str] = {
    "CWD-1002": "Memory", "CWD-1003": "Memory", "CWD-1007": "Memory",
    "CWD-1009": "Memory", "CWD-1015": "Memory", "CWD-1016": "Memory",
    "CWD-1017": "Memory", "CWD-1019": "Memory", "CWD-1021": "Memory",
    "CWD-1022": "Memory", "CWD-1023": "Memory", "CWD-1025": "Memory",
    "CWD-1026": "Memory", "CWD-1027": "Memory", "CWD-1028": "Memory",
    "CWD-1029": "Memory", "CWD-1030": "Memory", "CWD-1031": "Memory",
    "CWD-1034": "Memory", "CWD-1043": "Memory",
    "CWD-1005": "Logic",  "CWD-1006": "Logic",  "CWD-1008": "Logic",
    "CWD-1038": "Input",  "CWD-1039": "Input",  "CWD-1040": "Input",
    "CWD-1042": "Injection", "CWD-1068": "Injection", "CWD-1070": "Injection",
    "CWD-1071": "Injection", "CWD-1081": "Injection", "CWD-1082": "Injection",
    "CWD-1084": "Injection", "CWD-1093": "Injection", "CWD-1096": "Injection",
    "CWD-1101": "Injection", "CWD-1113": "Injection", "CWD-1114": "Injection",
    "CWD-1115": "Injection",
}


def load_best_prompts() -> Dict[str, str]:
    prompts: Dict[str, str] = {}
    for major, rnd in BEST_ROUNDS.items():
        path = Path(RESULTS_DIR) / major / f"round{rnd}.json"
        if path.exists():
            with open(path) as f:
                data = json.load(f)
            prompts[major] = data["prompt"]
        else:
            print(f"WARNING: {path} not found, skipping {major}")
    return prompts


def load_binary_prompt() -> Optional[str]:
    path = Path("binary_evolution_results") / f"round{BINARY_BEST_ROUND}.json"
    if path.exists():
        with open(path) as f:
            data = json.load(f)
        return data.get("prompt")
    return None


def combine_code(context: str, func: str, language: str) -> str:
    ctx = (context or "").strip()
    fn  = (func   or "").strip()
    if not ctx and not fn:
        return ""
    if not ctx:
        return fn
    if not fn:
        return ctx
    if language == "java":
        last = ctx.rfind("}")
        if last == -1:
            return ctx + "\n\n" + fn
        return ctx[:last] + "    " + fn + "\n}"
    return ctx + "\n\n" + fn


def extract_code(code_obj: dict, language: str) -> str:
    if not code_obj:
        return ""
    ctx  = code_obj.get("context") or ""
    func = code_obj.get("func")    or ""
    cls  = code_obj.get("class")   or ""
    if func:
        return combine_code(ctx or cls, func, language)
    return ctx or cls


def build_cascade_testset(raw_data: dict, per_cwd: int = 3, seed: int = SEED) -> List[dict]:
    """Build a test set from raw benchmark.

    Each sample has:
      - code, lang, cwd, true_major, true_label (VULNERABLE/BENIGN)
    """
    rng = random.Random(seed)
    samples: List[dict] = []

    for lang, cwd_dict in raw_data.items():
        for cwd_id, entries in cwd_dict.items():
            true_major = CWD_TO_MAJOR.get(cwd_id, "Unknown")

            vuln_for_cwd: List[dict] = []
            benign_for_cwd: List[dict] = []

            for entry in entries:
                vc = entry.get("vulnerable_code") or {}
                v_code = extract_code(vc, lang)
                if v_code.strip():
                    vuln_for_cwd.append({
                        "code": v_code, "lang": lang, "cwd": cwd_id,
                        "true_major": true_major, "true_label": "VULNERABLE",
                    })
                bc = entry.get("benign_code") or {}
                b_code = extract_code(bc, lang)
                if b_code.strip():
                    benign_for_cwd.append({
                        "code": b_code, "lang": lang, "cwd": cwd_id,
                        "true_major": "BENIGN", "true_label": "BENIGN",
                    })

            rng.shuffle(vuln_for_cwd)
            rng.shuffle(benign_for_cwd)
            samples.extend(vuln_for_cwd[:per_cwd])
            samples.extend(benign_for_cwd[:per_cwd])

    rng.shuffle(samples)
    return samples


def parse_prediction(text: str) -> Tuple[str, float]:
    m = re.search(r'\{[^{}]*"prediction"\s*:\s*"(\w+)"[^{}]*\}', text, re.IGNORECASE)
    if m:
        pred = m.group(1).upper()
        conf_m = re.search(r'"confidence"\s*:\s*([\d.]+)', text, re.IGNORECASE)
        conf = float(conf_m.group(1)) if conf_m else 0.5
        if pred in ("VULNERABLE", "BENIGN"):
            return pred, conf
    text_lower = text.lower()
    if "vulnerable" in text_lower:
        return "VULNERABLE", 0.5
    if "benign" in text_lower:
        return "BENIGN", 0.5
    return "UNKNOWN", 0.0


def run_cascade(
    samples: List[dict],
    prompts: Dict[str, str],
    binary_prompt: Optional[str] = None,
    verbose: bool = True,
) -> List[dict]:
    """For each sample, run all major prompts and determine cascade prediction.

    If binary_prompt is provided, uses two-stage cascade:
      Stage 1: binary classifier — if BENIGN, skip stage 2 and predict BENIGN
      Stage 2: major classifiers — pick highest-confidence VULNERABLE major
    """
    api_base = os.environ.get("OPENROUTER_API_BASE", "https://openrouter.ai/api/v1")
    api_key  = os.environ.get("OPENROUTER_API_KEY", "")
    model    = (os.environ.get("OPENROUTER_MODEL")
                or os.environ.get("MODEL_NAME")
                or "openai/gpt-5.4")
    majors   = list(prompts.keys())

    async def _run_all():
        aclient = AsyncOpenAI(base_url=api_base, api_key=api_key,
                              timeout=120.0, max_retries=1)
        sem = asyncio.Semaphore(CONCURRENCY)
        results: List[Optional[dict]] = [None] * len(samples)
        done = {"count": 0}

        async def _call_model(prompt: str) -> Tuple[str, float]:
            try:
                async with sem:
                    resp = await aclient.chat.completions.create(
                        model=model,
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.1,
                        max_tokens=MAX_TOKENS,
                    )
                text = resp.choices[0].message.content or ""
            except Exception as exc:
                text = f"ERROR: {exc}"
            return parse_prediction(text)

        async def _one_major(sample: dict, major: str, prompt_tmpl: str) -> Tuple[str, float, str]:
            code = sample["code"][:CODE_LIMIT]
            prompt = prompt_tmpl.replace("{code}", code)
            pred, conf = await _call_model(prompt)
            return major, pred, conf

        async def _process_sample(i: int, sample: dict):
            nonlocal done
            code = sample["code"][:CODE_LIMIT]

            # Stage 1: Binary classifier (optional)
            binary_pred = "VULNERABLE"  # default: proceed to stage 2
            if binary_prompt is not None:
                bp = binary_prompt.replace("{code}", code)
                bin_pred, bin_conf = await _call_model(bp)
                if bin_pred == "BENIGN":
                    # Short-circuit: skip major prompts
                    true_major = sample["true_major"]
                    true_label = sample["true_label"]
                    correct = (true_label == "BENIGN")
                    results[i] = {
                        "idx": i, "cwd": sample["cwd"],
                        "true_major": true_major, "true_label": true_label,
                        "lang": sample["lang"],
                        "pred_major": "BENIGN", "pred_label": "BENIGN",
                        "conf": bin_conf, "correct": correct,
                        "stage": 1,
                        "per_major": {"binary": ("BENIGN", bin_conf)},
                    }
                    done = done + 1 if isinstance(done, int) else done
                    done["count"] += 1
                    if verbose:
                        mark = "✓" if correct else "✗"
                        print(f"  [{done['count']:3d}/{len(samples)}] {mark}[gate=BENIGN] "
                              f"true={true_major:<12} {sample['cwd']}")
                    return

            # Stage 2: Major classifiers
            tasks = [_one_major(sample, m, prompts[m]) for m in majors]
            results_per_major = await asyncio.gather(*tasks)

            vuln_results = [(m, conf) for m, pred, conf in results_per_major
                            if pred == "VULNERABLE"]

            if vuln_results:
                best_major, best_conf = max(vuln_results, key=lambda x: x[1])
                pred_label = "VULNERABLE"
                pred_major = best_major
            else:
                pred_label = "BENIGN"
                pred_major = "BENIGN"
                best_conf = min(conf for _, _, conf in results_per_major)

            true_major = sample["true_major"]
            true_label = sample["true_label"]
            if true_label == "VULNERABLE":
                correct = (pred_major == true_major)
            else:
                correct = (pred_label == "BENIGN")

            detail = {m: (pred, conf) for m, pred, conf in results_per_major}
            results[i] = {
                "idx": i, "cwd": sample["cwd"],
                "true_major": true_major, "true_label": true_label,
                "lang": sample["lang"],
                "pred_major": pred_major, "pred_label": pred_label,
                "conf": best_conf, "correct": correct,
                "stage": 2,
                "per_major": detail,
            }
            done["count"] += 1
            if verbose:
                mark = "✓" if correct else "✗"
                stage = "[2]" if binary_prompt else "   "
                print(f"  [{done['count']:3d}/{len(samples)}] {mark}{stage} "
                      f"true={true_major:<12} pred={pred_major:<12} {sample['cwd']}")

        done = {"count": 0}
        await asyncio.gather(*[_process_sample(i, s) for i, s in enumerate(samples)])
        await aclient.close()
        return results

    return asyncio.run(_run_all())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-cwd", type=int, default=3,
                        help="Max samples per CWD per class (default: 3)")
    parser.add_argument("--out", default="cascade_eval_results.json",
                        help="Output file path")
    parser.add_argument("--two-stage", action="store_true",
                        help="Use two-stage cascade: binary gate then major classifier")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if not HAS_ASYNC_OPENAI:
        print("ERROR: openai package not installed.")
        sys.exit(1)

    # Load .env
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())
    if not os.environ.get("OPENROUTER_API_KEY"):
        print("ERROR: OPENROUTER_API_KEY not set")
        sys.exit(1)

    # Load prompts
    prompts = load_best_prompts()
    print(f"Loaded {len(prompts)} major prompts: {list(prompts.keys())}")

    binary_prompt = None
    if args.two_stage:
        binary_prompt = load_binary_prompt()
        if binary_prompt:
            print(f"Two-stage mode: using binary gate (round {BINARY_BEST_ROUND})")
        else:
            print(f"WARNING: binary_evolution_results/round{BINARY_BEST_ROUND}.json not found, "
                  f"falling back to single-stage")

    # Build test set
    with open(RAW_DATA) as f:
        raw_data = json.load(f)
    test_set = build_cascade_testset(raw_data, per_cwd=args.per_cwd)
    n_vuln   = sum(1 for s in test_set if s["true_label"] == "VULNERABLE")
    n_benign = sum(1 for s in test_set if s["true_label"] == "BENIGN")
    print(f"\nTest set: {len(test_set)} samples  (VULN={n_vuln}, BENIGN={n_benign})")

    # Run cascade evaluation
    mode_str = "two-stage" if binary_prompt else "single-stage"
    print(f"\nRunning {mode_str} cascade ({len(prompts)} major prompts, "
          f"concurrency={CONCURRENCY})...")
    t0 = time.time()
    results = run_cascade(test_set, prompts, binary_prompt=binary_prompt,
                          verbose=not args.quiet)
    elapsed = time.time() - t0

    # Metrics
    correct = sum(r["correct"] for r in results if r is not None)
    total   = len([r for r in results if r is not None])
    accuracy = correct / total if total else 0.0

    # Per-major accuracy
    from collections import defaultdict, Counter
    major_correct: Dict[str, int] = defaultdict(int)
    major_total:   Dict[str, int] = defaultdict(int)
    major_fp: Dict[str, int] = defaultdict(int)   # predicted as this major incorrectly
    major_fn: Dict[str, int] = defaultdict(int)   # true major but predicted wrong

    for r in results:
        if r is None:
            continue
        tm = r["true_major"]
        pm = r["pred_major"]
        major_total[tm] += 1
        if r["correct"]:
            major_correct[tm] += 1
        elif r["true_label"] == "VULNERABLE":
            major_fn[tm] += 1
        if r["pred_label"] == "VULNERABLE" and not r["correct"]:
            major_fp[pm] += 1

    print(f"\n{'='*65}")
    print(f"CASCADE ACCURACY: {accuracy:.1%}  ({correct}/{total})  elapsed={elapsed:.0f}s")
    print(f"{'='*65}")
    print(f"\nPer-major breakdown:")
    for major in list(prompts.keys()) + ["BENIGN", "Unknown"]:
        if major_total[major] > 0:
            acc = major_correct[major] / major_total[major]
            print(f"  {major:<12}: {acc:.1%}  ({major_correct[major]}/{major_total[major]})  "
                  f"FN={major_fn[major]}  FP={major_fp[major]}")

    # Wrong predictions analysis
    wrong = [r for r in results if r and not r["correct"]]
    print(f"\nWrong predictions ({len(wrong)}):")
    for r in wrong[:20]:
        print(f"  [{r['idx']:3d}] true={r['true_major']:<12} pred={r['pred_major']:<12} "
              f"cwd={r['cwd']} lang={r['lang']}")

    # Save results
    out_path = Path(args.out)
    with open(out_path, "w") as f:
        json.dump({
            "accuracy": accuracy,
            "correct": correct,
            "total": total,
            "elapsed_s": round(elapsed, 1),
            "per_major": {
                m: {
                    "accuracy": major_correct[m] / major_total[m] if major_total[m] else 0,
                    "correct": major_correct[m],
                    "total": major_total[m],
                    "fn": major_fn[m],
                    "fp": major_fp[m],
                }
                for m in set(list(prompts.keys()) + ["BENIGN"])
                if major_total[m] > 0
            },
            "wrong_samples": wrong,
            "best_rounds": BEST_ROUNDS,
        }, f, ensure_ascii=False, indent=2)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
