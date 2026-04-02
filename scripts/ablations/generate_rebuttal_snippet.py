#!/usr/bin/env python3
"""Generate markdown snippet for OpenReview rebuttal."""

import json
import sys
from pathlib import Path


def load_all_results(output_dir: Path) -> dict:
    """Load all experiment results.

    Args:
        output_dir: Directory containing experiment outputs

    Returns:
        Dictionary with loaded results keyed by experiment type
    """
    results = {}

    # Load baseline comparison
    baseline_path = output_dir / "metrics" / "baseline_comparison.json"
    if baseline_path.exists():
        with open(baseline_path) as f:
            results["baselines"] = json.load(f)

    # Load pairing ablation
    pairing_path = output_dir / "metrics" / "pairing_ablation.json"
    if pairing_path.exists():
        with open(pairing_path) as f:
            results["pairing"] = json.load(f)

    # Load clean pool sensitivity
    sensitivity_path = output_dir / "metrics" / "clean_pool_sensitivity.json"
    if sensitivity_path.exists():
        with open(sensitivity_path) as f:
            results["sensitivity"] = json.load(f)

    return results


def _fmt(value, fmt=".2f"):
    """Format a numeric value, returning '-' if missing."""
    if value is None:
        return "-"
    return f"{value:{fmt}}"


def generate_snippet(results: dict) -> str:
    """Generate markdown tables for the rebuttal.

    Args:
        results: Dictionary of experiment results from load_all_results()

    Returns:
        Markdown string with formatted tables
    """
    baselines = results.get("baselines", {})
    pairing = results.get("pairing", {})
    sensitivity = results.get("sensitivity", {})

    # Table R1: Baseline Comparison
    r1_methods = [
        ("GPT-4o (no RAG)", baselines.get("gpt4o_no_rag", {})),
        ("GPT-4o + RAG (single-pass)", baselines.get("gpt4o_rag_singlepass", {})),
        ("Single-Agent + Tool + RAG", baselines.get("single_agent_tool_rag", {})),
        ("**MulVul (Ours)**", baselines.get("mulvul", {})),
    ]

    r1_rows = []
    for name, data in r1_methods:
        macro_f1 = _fmt(data.get("macro_f1"))
        llm_calls = _fmt(data.get("avg_llm_calls"), ".1f")
        retrieval = _fmt(data.get("avg_retrieval_calls"), ".1f")
        time_ms = _fmt(data.get("avg_time_ms"), ".0f")
        if name.startswith("**"):
            r1_rows.append(f"| {name} | **{macro_f1}** | {llm_calls} | {retrieval} | {time_ms} |")
        else:
            r1_rows.append(f"| {name} | {macro_f1} | {llm_calls} | {retrieval} | {time_ms} |")
    r1_table = "\n".join(r1_rows)

    # Table R2: Cross-Model Pairing Ablation
    r2_pairings = [
        ("Claude → GPT-4o (MulVul)", pairing.get("claude_to_gpt4o", {})),
        ("GPT-4o → GPT-4o", pairing.get("gpt4o_to_gpt4o", {})),
    ]

    r2_rows = []
    for name, data in r2_pairings:
        macro_f1 = _fmt(data.get("macro_f1"))
        evo_cost = _fmt(data.get("evolution_cost_tokens"), ",.0f")
        r2_rows.append(f"| {name} | {macro_f1} | {evo_cost} |")
    r2_table = "\n".join(r2_rows)

    # Table R3: Clean Pool Size Sensitivity
    r3_fracs = ["0.1", "0.25", "0.5", "1.0"]
    r3_rows = []
    for frac in r3_fracs:
        data = sensitivity.get(frac, {})
        macro_f1 = _fmt(data.get("macro_f1"))
        precision = _fmt(data.get("precision"))
        fp_rate = _fmt(data.get("fp_rate"))
        pct = f"{float(frac) * 100:.0f}%"
        r3_rows.append(f"| {pct} | {macro_f1} | {precision} | {fp_rate} |")
    r3_table = "\n".join(r3_rows)

    snippet = f"""## Supplementary Experiment Results

### Table R1: Baseline Comparison (Full PrimeVul Test Set)

| Method | Macro-F1 | Avg LLM Calls | Avg Retrieval | Avg Time (ms) |
|--------|----------|---------------|---------------|---------------|
{r1_table}

### Table R2: Cross-Model Pairing Ablation

| Generator → Executor | Macro-F1 | Evolution Cost (tokens) |
|---------------------|----------|------------------------|
{r2_table}

### Table R3: Clean Pool Size Sensitivity

| Clean Pool Fraction | Macro-F1 | Precision | FP Rate |
|--------------------|----------|-----------|---------|
{r3_table}

---
*Results generated automatically. Update with actual values after running experiments.*
"""
    return snippet


def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_rebuttal_snippet.py <output_dir>")
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    results = load_all_results(output_dir)

    snippet = generate_snippet(results)

    # Save snippet
    snippet_path = output_dir / "rebuttal_snippet.md"
    snippet_path.parent.mkdir(parents=True, exist_ok=True)
    with open(snippet_path, "w") as f:
        f.write(snippet)

    print(f"Rebuttal snippet saved to: {snippet_path}")
    print("\n" + "=" * 60)
    print(snippet)


if __name__ == "__main__":
    main()
