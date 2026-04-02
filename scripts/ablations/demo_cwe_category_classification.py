#!/usr/bin/env python3
"""
CWE Category Classification Demo

This demo focuses on classifying code into CWE major categories:
- Memory (buffer overflow, use-after-free, etc.)
- Injection (SQL injection, XSS, etc.)
- Logic (authentication, race conditions, etc.)
- Input (input validation, path traversal, etc.)
- Crypto (cryptographic weaknesses)

No binary vulnerable/benign classification - directly classify to categories.
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.multiagent.agents import create_detection_agent, create_meta_agent
from evoprompt.multiagent.coordinator import MultiAgentCoordinator, CoordinatorConfig, CoordinationStrategy
from evoprompt.data.dataset import PrimevulDataset
from evoprompt.llm.client import load_env_vars, create_llm_client, create_meta_prompt_client
from evoprompt.evaluators.cwe_category_evaluator import CWECategoryEvaluator
from evoprompt.prompts.hierarchical import CWECategory


def setup_environment():
    """Setup and verify environment."""
    load_env_vars()

    api_key = os.getenv("API_KEY")
    if not api_key:
        print("❌ API_KEY not found")
        return False

    print("✅ Environment configured:")
    print(f"   Detection Model: {os.getenv('MODEL_NAME', 'gpt-4')}")
    print(f"   Meta Model: {os.getenv('META_MODEL_NAME', 'claude-4.5')}")

    return True


def create_category_classification_prompts():
    """Create prompts for CWE category classification.

    These prompts ask the LLM to classify code into CWE categories,
    not just vulnerable/benign.
    """
    return [
        # Direct category classification
        """Classify this code into a security vulnerability category:

Categories:
- Memory: Buffer overflow, use-after-free, NULL pointer, memory corruption
- Injection: SQL injection, XSS, command injection
- Logic: Authentication bypass, race conditions, logic errors
- Input: Input validation, path traversal
- Crypto: Cryptographic weaknesses
- Benign: No significant vulnerabilities

Code to analyze:
{input}

Category:""",

        # Expert-guided classification
        """You are a security expert. Classify this code's primary security concern:

Code:
{input}

Choose ONE category:
1. Memory - Memory safety issues (buffer overflow, use-after-free, NULL pointer)
2. Injection - Injection vulnerabilities (SQL, XSS, command injection)
3. Logic - Logic flaws (authentication, authorization, race conditions)
4. Input - Input handling (validation, path traversal)
5. Crypto - Cryptographic issues
6. Benign - Safe code

Answer with just the category name:""",

        # CWE-focused classification
        """Identify the CWE category for this code:

{input}

Categories:
- Memory (CWE-120, CWE-787, CWE-416, CWE-476, CWE-190)
- Injection (CWE-79, CWE-89, CWE-78)
- Logic (authentication, race conditions)
- Input (CWE-22, CWE-20)
- Crypto (weak cryptography)
- Benign (safe)

Category:""",

        # Detailed analysis classification
        """Analyze this code for security vulnerabilities and classify into the PRIMARY category:

Code:
{input}

Classification options:
- Memory: If code has buffer overflows, memory leaks, use-after-free, null pointer issues
- Injection: If code is vulnerable to SQL injection, XSS, or command injection
- Logic: If code has authentication/authorization flaws or race conditions
- Input: If code has input validation or path traversal issues
- Crypto: If code uses weak cryptography
- Benign: If code appears safe

Primary category:""",
    ]


def run_category_demo(data_dir: str, output_dir: str, max_samples: int = 100):
    """Run CWE category classification demo."""
    print("\n🎯 CWE Category Classification Demo")
    print("=" * 70)
    print("Focus: Direct category classification (not vulnerable/benign)")
    print()

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exp_name = f"cwe_category_{timestamp}"
    exp_dir = Path(output_dir) / exp_name
    exp_dir.mkdir(parents=True, exist_ok=True)

    print(f"📂 Experiment: {exp_dir}")

    # Load dataset
    print(f"\n📊 Loading dataset from {data_dir}...")
    dev_file = Path(data_dir) / "dev.txt"

    if not dev_file.exists():
        print(f"❌ Dataset not found: {dev_file}")
        return False

    dataset = PrimevulDataset(str(dev_file), split="dev")
    total_samples = len(dataset)
    print(f"   ✅ Loaded {total_samples} samples")

    if total_samples > max_samples:
        print(f"   🔍 Using first {max_samples} samples")

    # Show sample distribution
    print("\n📋 Sample inspection:")
    samples = dataset.get_samples(10)
    category_counts = {}
    for s in samples:
        if hasattr(s, 'metadata') and 'cwe' in s.metadata:
            cwes = s.metadata['cwe']
            if cwes:
                from evoprompt.prompts.hierarchical import get_cwe_major_category
                cat = get_cwe_major_category(cwes[0])
                cat_name = cat.value if cat else "Unknown"
                category_counts[cat_name] = category_counts.get(cat_name, 0) + 1

    print("   Category distribution (first 10 samples):")
    for cat, count in sorted(category_counts.items()):
        print(f"   - {cat}: {count}")

    # Create LLM client
    print("\n🤖 Initializing detection agent...")
    detection_model = os.getenv("MODEL_NAME", "gpt-4")
    detection_client = create_llm_client(llm_type=detection_model)
    print(f"   ✅ Detection Model: {detection_model}")

    # Create category evaluator
    evaluator = CWECategoryEvaluator(
        dataset=dataset,
        llm_client=detection_client
    )

    # Create initial prompts
    initial_prompts = create_category_classification_prompts()
    print(f"\n🎯 Testing {len(initial_prompts)} category classification prompts")

    # Save initial prompts
    prompts_file = exp_dir / "initial_prompts.txt"
    with open(prompts_file, "w") as f:
        f.write("CWE Category Classification Prompts\n")
        f.write("=" * 70 + "\n\n")
        for i, prompt in enumerate(initial_prompts, 1):
            f.write(f"Prompt {i}:\n")
            f.write("-" * 70 + "\n")
            f.write(prompt + "\n\n")

    # Test each prompt
    print("\n🧪 Testing prompts...")
    results = []

    for i, prompt in enumerate(initial_prompts, 1):
        print(f"\n📝 Prompt {i}/{len(initial_prompts)}")
        print(f"   Preview: {prompt[:100]}...")

        start = time.time()

        try:
            # Evaluate with limited samples
            stats = evaluator.evaluate(prompt, sample_size=max_samples)
            summary = stats.get_summary()

            elapsed = time.time() - start

            # Display results
            accuracy = summary.get('accuracy', 0)
            print(f"   ✅ Accuracy: {accuracy:.2%} ({elapsed:.1f}s)")

            # Show per-category performance
            if 'category_stats' in summary:
                print(f"   📊 Per-category accuracy:")
                for cat, cat_stats in sorted(summary['category_stats'].items()):
                    cat_acc = cat_stats.get('accuracy', 0)
                    total = cat_stats.get('total', 0)
                    status = "✅" if cat_acc >= 0.6 else "⚠️" if cat_acc >= 0.4 else "❌"
                    print(f"      {status} {cat}: {cat_acc:.1%} ({total} samples)")

            results.append({
                "prompt_id": i,
                "prompt": prompt,
                "accuracy": accuracy,
                "summary": summary,
                "elapsed_time": elapsed
            })

        except Exception as e:
            print(f"   ❌ Evaluation failed: {e}")
            results.append({
                "prompt_id": i,
                "prompt": prompt,
                "accuracy": 0.0,
                "error": str(e)
            })

    # Find best prompt
    print("\n" + "=" * 70)
    print("📊 Results Summary")
    print("=" * 70)

    best_result = max(results, key=lambda x: x.get('accuracy', 0))
    print(f"\n🏆 Best Prompt: #{best_result['prompt_id']}")
    print(f"   Accuracy: {best_result['accuracy']:.2%}")

    if 'summary' in best_result and 'category_stats' in best_result['summary']:
        print(f"\n   Category Performance:")
        for cat, stats in sorted(best_result['summary']['category_stats'].items()):
            acc = stats.get('accuracy', 0)
            total = stats.get('total', 0)
            print(f"   - {cat}: {acc:.1%} ({total} samples)")

    # Save results
    results_file = exp_dir / "evaluation_results.json"
    with open(results_file, "w") as f:
        # Make results JSON-serializable
        serializable_results = []
        for r in results:
            sr = {
                "prompt_id": r["prompt_id"],
                "prompt": r["prompt"],
                "accuracy": float(r.get("accuracy", 0)),
                "elapsed_time": r.get("elapsed_time", 0)
            }
            if "error" in r:
                sr["error"] = r["error"]
            serializable_results.append(sr)

        json.dump({
            "experiment_name": exp_name,
            "timestamp": timestamp,
            "dataset": str(dev_file),
            "max_samples": max_samples,
            "best_prompt_id": best_result["prompt_id"],
            "best_accuracy": float(best_result["accuracy"]),
            "results": serializable_results
        }, f, indent=2, ensure_ascii=False)

    # Save best prompt details
    best_file = exp_dir / "best_prompt.txt"
    with open(best_file, "w") as f:
        f.write("Best Performing Category Classification Prompt\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Prompt ID: {best_result['prompt_id']}\n")
        f.write(f"Accuracy: {best_result['accuracy']:.2%}\n\n")
        f.write("Prompt:\n")
        f.write("-" * 70 + "\n")
        f.write(best_result['prompt'] + "\n")

    print(f"\n💾 Results saved to: {exp_dir}")
    print(f"   - {prompts_file.name}")
    print(f"   - {results_file.name}")
    print(f"   - {best_file.name}")

    print("\n✨ Next Steps:")
    print("   1. Review best_prompt.txt for the top-performing prompt")
    print("   2. Use this prompt as baseline for evolution")
    print("   3. Focus on improving categories with low accuracy")

    return True


def main():
    """Main entry point."""
    if not setup_environment():
        return 1

    # Use full dataset
    data_dir = "./data/primevul_1percent_sample"
    if not os.path.exists(data_dir):
        data_dir = "./data/demo_primevul_1percent_sample"
        print(f"⚠️  Using demo dataset: {data_dir}")

    if not os.path.exists(data_dir):
        print("❌ No dataset found")
        return 1

    output_dir = "./outputs/cwe_category"

    # Run demo
    success = run_category_demo(data_dir, output_dir, max_samples=100)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
