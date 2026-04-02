#!/usr/bin/env python3
"""
Multi-agent Coevolution with Debug Output

This version includes detailed logging to help diagnose issues.
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
from evoprompt.algorithms.coevolution import CoevolutionaryAlgorithm
from evoprompt.data.dataset import PrimevulDataset
from evoprompt.llm.client import load_env_vars, create_llm_client, create_meta_prompt_client


def setup_environment():
    """Setup environment and check API keys."""
    load_env_vars()

    api_key = os.getenv("API_KEY")
    if not api_key:
        print("❌ API_KEY not found in environment")
        return False

    meta_model = os.getenv("META_MODEL_NAME", "claude-sonnet-4-5-20250929-thinking")

    print("✅ Environment configured:")
    print(f"   Detection Model: {os.getenv('MODEL_NAME', 'gpt-4')}")
    print(f"   Meta Model: {meta_model}")
    print(f"   API Base: {os.getenv('API_BASE_URL', 'default')}")

    return True


def create_initial_prompts():
    """Create initial prompts for coevolution."""
    return [
        """Analyze this code for security vulnerabilities. Look for common issues like buffer overflows, injection attacks, and unsafe operations.

Code:
{input}

Respond with 'vulnerable' if you find security issues, or 'benign' if the code is safe:""",

        """You are a security expert. Examine this code for CWE patterns:
- CWE-120: Buffer overflow
- CWE-79: Cross-site scripting
- CWE-89: SQL injection

Code:
{input}

Classification ('vulnerable' or 'benign'):""",

        """Security analysis:
1. Check for unsafe function calls
2. Look for injection vulnerabilities
3. Identify memory issues

Code:
{input}

Is this code vulnerable? Answer 'vulnerable' or 'benign':""",

        """Think like an attacker: Can you exploit this code?

Code:
{input}

Verdict ('vulnerable' if exploitable, 'benign' if safe):""",
    ]


def run_debug_demo(data_dir: str, output_dir: str, max_samples: int = 50):
    """Run demo with debug output."""
    print("\n🐛 Multi-Agent Coevolution - Debug Mode")
    print("=" * 70)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exp_name = f"debug_coevo_{timestamp}"
    exp_dir = Path(output_dir) / exp_name
    exp_dir.mkdir(parents=True, exist_ok=True)

    print(f"📂 Experiment directory: {exp_dir}")

    # Load dataset
    print(f"\n📊 Loading dataset from {data_dir}...")
    dev_file = Path(data_dir) / "dev.txt"

    if not dev_file.exists():
        print(f"❌ Dataset not found: {dev_file}")
        return False

    dataset = PrimevulDataset(str(dev_file), split="dev")
    print(f"   ✅ Loaded {len(dataset)} samples")

    # Limit samples for debugging
    if len(dataset) > max_samples:
        print(f"   🔍 Using first {max_samples} samples for debugging")

    # Show sample data
    print("\n📋 Sample data inspection:")
    sample = dataset.get_samples(1)[0]
    print(f"   Sample ID: {getattr(sample, 'id', 'N/A')}")
    print(f"   Input text length: {len(sample.input_text)} chars")
    print(f"   Target: {sample.target}")
    print(f"   Code preview: {sample.input_text[:100]}...")

    # Create agents
    print("\n🤖 Initializing agents...")

    detection_model = os.getenv("MODEL_NAME", "gpt-4")
    detection_client = create_llm_client(llm_type=detection_model)
    detection_agent = create_detection_agent(
        model_name=detection_model,
        temperature=0.1,
        llm_client=detection_client
    )
    print(f"   ✅ Detection Agent: {detection_agent.config.model_name}")

    meta_model = os.getenv("META_MODEL_NAME", "claude-sonnet-4-5-20250929-thinking")
    meta_client = create_meta_prompt_client(model_name=meta_model)
    meta_agent = create_meta_agent(
        model_name=meta_model,
        temperature=0.7,
        llm_client=meta_client
    )
    print(f"   ✅ Meta Agent: {meta_agent.config.model_name}")

    # Test detection on a single sample
    print("\n🧪 Testing detection agent...")
    test_prompt = "Analyze this code for vulnerabilities. Respond 'vulnerable' or 'benign':\n\n{input}\n\nAnswer:"
    test_samples = dataset.get_samples(3)
    test_predictions = detection_agent.detect(
        test_prompt,
        [s.input_text for s in test_samples]
    )

    print("   Test predictions:")
    for i, (sample, pred) in enumerate(zip(test_samples, test_predictions)):
        actual = "vulnerable" if sample.target == 1 else "benign"
        match = "✅" if pred == actual else "❌"
        print(f"   {match} Sample {i+1}: Predicted '{pred}', Actual '{actual}'")

    # Create coordinator
    coordinator_config = CoordinatorConfig(
        strategy=CoordinationStrategy.SEQUENTIAL,
        batch_size=16,
        enable_batch_feedback=True,
        statistics_window=3
    )

    coordinator = MultiAgentCoordinator(
        detection_agent=detection_agent,
        meta_agent=meta_agent,
        config=coordinator_config
    )
    print(f"\n   ✅ Coordinator configured (batch_size={coordinator_config.batch_size})")

    # Create algorithm with smaller parameters for debugging
    coevo_config = {
        "population_size": 4,  # Smaller for debugging
        "max_generations": 2,   # Fewer generations
        "mutation_rate": 0.2,
        "top_k": 2,
        "enable_elitism": True,
        "meta_improvement_rate": 0.5,
    }

    algorithm = CoevolutionaryAlgorithm(
        config=coevo_config,
        coordinator=coordinator,
        dataset=dataset
    )

    print(f"\n🧬 Algorithm configured:")
    print(f"   Population: {coevo_config['population_size']}")
    print(f"   Generations: {coevo_config['max_generations']}")

    # Create initial prompts
    initial_prompts = create_initial_prompts()
    print(f"\n🎯 Using {len(initial_prompts)} initial prompts")

    # Save config
    config_file = exp_dir / "debug_config.json"
    with open(config_file, "w") as f:
        json.dump({
            "experiment_name": exp_name,
            "dataset_file": str(dev_file),
            "dataset_size": len(dataset),
            "max_samples": max_samples,
            "detection_model": detection_model,
            "meta_model": meta_model,
            "algorithm_config": coevo_config,
        }, f, indent=2)

    # Run evolution
    print("\n🚀 Starting evolution...")
    print("-" * 70)

    start_time = time.time()

    try:
        results = algorithm.evolve(initial_prompts=initial_prompts)

        elapsed = time.time() - start_time

        # Print results
        print("\n" + "=" * 70)
        print("✅ Evolution Complete!")
        print("=" * 70)

        print(f"\n⏱️  Time: {elapsed:.1f}s")
        print(f"📈 Best Fitness: {results['best_fitness']:.4f}")

        if len(results['fitness_history']) > 1:
            improvement = results['fitness_history'][-1] - results['fitness_history'][0]
            print(f"📊 Improvement: {improvement:+.4f}")

        print(f"\n📝 Fitness History:")
        for i, f in enumerate(results['fitness_history']):
            print(f"   Gen {i}: {f:.4f}")

        # Save results
        results_file = exp_dir / "debug_results.json"
        with open(results_file, "w") as f:
            json.dump({
                "best_fitness": float(results['best_fitness']),
                "best_prompt": results['best_prompt'],
                "fitness_history": [float(f) for f in results['fitness_history']],
                "generation_stats": results.get('generation_stats', []),
                "elapsed_time": elapsed,
            }, f, indent=2, ensure_ascii=False)

        # Export statistics
        stats_file = exp_dir / "debug_statistics.json"
        coordinator.export_statistics(str(stats_file))

        print(f"\n💾 Results saved to: {exp_dir}")
        print(f"   - {config_file.name}")
        print(f"   - {results_file.name}")
        print(f"   - {stats_file.name}")

        # Show coordinator insights
        coord_stats = results.get('coordinator_statistics', {})
        if coord_stats:
            print(f"\n📊 Coordinator Statistics:")
            print(f"   Generations: {coord_stats.get('total_generations', 0)}")
            print(f"   Batches: {coord_stats.get('total_batches', 0)}")

            suggestions = coord_stats.get('improvement_suggestions', [])
            if suggestions:
                print(f"\n💡 Top Suggestions:")
                for s in suggestions[:3]:
                    print(f"   - {s}")

        return True

    except Exception as e:
        print(f"\n❌ Error during evolution: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    if not setup_environment():
        return 1

    # Use the larger dataset by default
    data_dir = "./data/primevul_1percent_sample"

    if not os.path.exists(data_dir):
        data_dir = "./data/demo_primevul_1percent_sample"
        print(f"⚠️  Using demo dataset (small): {data_dir}")
    else:
        print(f"✅ Using full 1% sample dataset: {data_dir}")

    output_dir = "./outputs/multiagent_debug"

    # Run with limited samples for debugging
    success = run_debug_demo(data_dir, output_dir, max_samples=50)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
