#!/usr/bin/env python3
"""
Multi-agent Collaborative Prompt Evolution Demo

This script demonstrates the multi-agent coevolution framework for vulnerability detection:

Architecture:
- Detection Agent (GPT-4): Performs vulnerability detection on code samples
- Meta Agent (Claude 4.5): Analyzes performance and optimizes prompts
- Coordinator: Orchestrates collaboration between agents

Key Features:
1. Batch-based evaluation with detailed statistics
2. Meta-agent guided prompt improvement using historical feedback
3. Category-specific error analysis
4. Hierarchical prompt structure support
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.multiagent.agents import create_detection_agent, create_meta_agent
from evoprompt.multiagent.coordinator import MultiAgentCoordinator, CoordinatorConfig, CoordinationStrategy
from evoprompt.algorithms.coevolution import CoevolutionaryAlgorithm
from evoprompt.data.dataset import PrimevulDataset
from evoprompt.llm.client import load_env_vars, create_llm_client, create_meta_prompt_client


def setup_environment():
    """Setup environment and check API keys."""
    load_env_vars()

    # Check for required API keys
    api_key = os.getenv("API_KEY")
    if not api_key:
        print("❌ API_KEY not found in environment")
        print("   Please set API_KEY in .env file or environment")
        return False

    # Meta model configuration (optional, can use same API)
    meta_api_key = os.getenv("META_API_KEY") or api_key
    meta_model = os.getenv("META_MODEL_NAME", "claude-sonnet-4-5-20250929-thinking")

    print("✅ Environment configured:")
    print(f"   Detection Model: {os.getenv('MODEL_NAME', 'gpt-4')}")
    print(f"   Meta Model: {meta_model}")
    print(f"   API Base: {os.getenv('API_BASE_URL', 'default')}")

    return True


def create_initial_prompts_for_coevolution():
    """Create initial prompts optimized for multi-agent coevolution."""
    return [
        # Baseline security prompt
        """Analyze this code for security vulnerabilities. Look for common issues like buffer overflows, injection attacks, and unsafe operations.

Code:
{input}

Respond with 'vulnerable' if you find security issues, or 'benign' if the code is safe:""",

        # CWE-focused prompt
        """You are a security expert. Examine this code for CWE (Common Weakness Enumeration) patterns:
- CWE-120: Buffer overflow
- CWE-79: Cross-site scripting
- CWE-89: SQL injection
- CWE-476: NULL pointer dereference
- CWE-416: Use after free

Code:
{input}

Classification ('vulnerable' or 'benign'):""",

        # Detailed analysis prompt
        """Perform a thorough security analysis of this code:

1. Memory Safety: Check for buffer overflows, use-after-free, NULL dereferences
2. Input Validation: Look for injection vulnerabilities (SQL, XSS, command injection)
3. Logic Errors: Identify authentication bypasses, race conditions

Code to analyze:
{input}

Is this code vulnerable? Answer 'vulnerable' or 'benign':""",

        # Attack-oriented prompt
        """Think like an attacker: Can you exploit this code?

Look for:
- Unsafe function calls (strcpy, sprintf, system)
- Missing input validation
- Memory management errors
- Injection points

Code:
{input}

Verdict ('vulnerable' if exploitable, 'benign' if safe):""",
    ]


def run_multiagent_demo(data_dir: str, output_dir: str):
    """Run multi-agent coevolution demonstration."""
    print("\n🤖 Multi-Agent Collaborative Prompt Evolution")
    print("=" * 70)

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    exp_name = f"multiagent_coevo_{timestamp}"
    exp_dir = Path(output_dir) / exp_name
    exp_dir.mkdir(parents=True, exist_ok=True)

    print(f"📂 Experiment directory: {exp_dir}")

    # Load dataset
    print("\n📊 Loading dataset...")
    dev_file = Path(data_dir) / "dev.txt"

    if not dev_file.exists():
        print(f"❌ Dataset not found: {dev_file}")
        print("   Please run data sampling first:")
        print("   uv run python scripts/ablations/demo_primevul_1percent.py")
        return

    dataset = PrimevulDataset(str(dev_file), split="dev")
    print(f"   Loaded {len(dataset)} samples")

    # Create agents
    print("\n🤖 Initializing multi-agent system...")

    # Detection Agent (GPT-4 or configured model)
    detection_model = os.getenv("MODEL_NAME", "gpt-4")
    detection_client = create_llm_client(llm_type=detection_model)
    detection_agent = create_detection_agent(
        model_name=detection_model,
        temperature=0.1,
        llm_client=detection_client
    )
    print(f"   ✅ Detection Agent: {detection_agent.config.model_name}")

    # Meta Agent (Claude 4.5)
    meta_model = os.getenv("META_MODEL_NAME", "claude-sonnet-4-5-20250929-thinking")
    meta_client = create_meta_prompt_client(model_name=meta_model)
    meta_agent = create_meta_agent(
        model_name=meta_model,
        temperature=0.7,
        llm_client=meta_client
    )
    print(f"   ✅ Meta Agent: {meta_agent.config.model_name}")

    # Create coordinator
    coordinator_config = CoordinatorConfig(
        strategy=CoordinationStrategy.SEQUENTIAL,
        batch_size=16,  # Process 16 samples per batch
        enable_batch_feedback=True,
        statistics_window=3
    )

    coordinator = MultiAgentCoordinator(
        detection_agent=detection_agent,
        meta_agent=meta_agent,
        config=coordinator_config
    )
    print(f"   ✅ Coordinator: {coordinator_config.strategy.value} mode")

    # Create coevolutionary algorithm
    print("\n🧬 Configuring coevolutionary algorithm...")
    coevo_config = {
        "population_size": 6,
        "max_generations": 4,
        "mutation_rate": 0.2,
        "top_k": 3,  # Keep top 3 prompts
        "enable_elitism": True,
        "meta_improvement_rate": 0.5,  # Meta-improve 50% of population
    }

    algorithm = CoevolutionaryAlgorithm(
        config=coevo_config,
        coordinator=coordinator,
        dataset=dataset
    )

    print(f"   Population size: {coevo_config['population_size']}")
    print(f"   Generations: {coevo_config['max_generations']}")
    print(f"   Meta-improvement rate: {coevo_config['meta_improvement_rate']:.0%}")

    # Create initial prompts
    initial_prompts = create_initial_prompts_for_coevolution()
    print(f"\n🎯 Initial prompts: {len(initial_prompts)}")

    # Save initial prompts
    initial_prompts_file = exp_dir / "initial_prompts.txt"
    with open(initial_prompts_file, "w", encoding="utf-8") as f:
        f.write("Initial Prompts for Multi-Agent Coevolution\n")
        f.write("=" * 70 + "\n\n")
        for i, prompt in enumerate(initial_prompts, 1):
            f.write(f"Prompt {i}:\n")
            f.write("-" * 40 + "\n")
            f.write(prompt + "\n\n")

    # Save experiment configuration
    config_file = exp_dir / "experiment_config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump({
            "experiment_name": exp_name,
            "timestamp": timestamp,
            "detection_agent": {
                "model": detection_model,
                "temperature": 0.1,
            },
            "meta_agent": {
                "model": meta_model,
                "temperature": 0.7,
            },
            "coordinator": {
                "strategy": coordinator_config.strategy.value,
                "batch_size": coordinator_config.batch_size,
            },
            "algorithm": coevo_config,
            "dataset": {
                "file": str(dev_file),
                "size": len(dataset),
            }
        }, f, indent=2, ensure_ascii=False)

    # Run evolution
    print("\n🚀 Starting multi-agent coevolution...")
    print("-" * 70)

    start_time = time.time()

    try:
        results = algorithm.evolve(initial_prompts=initial_prompts)

        elapsed_time = time.time() - start_time

        # Save results
        print("\n💾 Saving results...")

        results_file = exp_dir / "evolution_results.json"
        with open(results_file, "w", encoding="utf-8") as f:
            # Convert numpy types to native Python types for JSON serialization
            serializable_results = {
                "best_prompt": results["best_prompt"],
                "best_fitness": float(results["best_fitness"]),
                "fitness_history": [float(f) for f in results["fitness_history"]],
                "generation_stats": results["generation_stats"],
                "coordinator_statistics": results["coordinator_statistics"],
                "elapsed_time_seconds": elapsed_time,
            }
            json.dump(serializable_results, f, indent=2, ensure_ascii=False)

        # Save final population
        population_file = exp_dir / "final_population.txt"
        with open(population_file, "w", encoding="utf-8") as f:
            f.write("Final Population - Top Prompts\n")
            f.write("=" * 70 + "\n\n")
            for i, ind in enumerate(results["final_population"][:5], 1):
                f.write(f"Rank {i} (Fitness: {ind['fitness']:.4f})\n")
                f.write("-" * 70 + "\n")
                f.write(ind["prompt"] + "\n\n")

        # Export statistics
        stats_file = exp_dir / "statistics.json"
        coordinator.export_statistics(str(stats_file))

        # Print summary
        print("\n" + "=" * 70)
        print("🎉 Multi-Agent Coevolution Complete!")
        print("=" * 70)

        print(f"\n⏱️  Time: {elapsed_time:.1f} seconds")
        print(f"📈 Best Fitness: {results['best_fitness']:.4f}")
        print(f"📊 Fitness Improvement: {results['fitness_history'][-1] - results['fitness_history'][0]:+.4f}")

        print("\n📝 Fitness History:")
        for i, fitness in enumerate(results['fitness_history']):
            print(f"   Generation {i}: {fitness:.4f}")

        print(f"\n🏆 Best Prompt:")
        print("-" * 70)
        print(results['best_prompt'])
        print("-" * 70)

        print(f"\n📂 Results saved to: {exp_dir}")
        print("\nGenerated files:")
        print(f"   ✅ {initial_prompts_file.name}")
        print(f"   ✅ {config_file.name}")
        print(f"   ✅ {results_file.name}")
        print(f"   ✅ {population_file.name}")
        print(f"   ✅ {stats_file.name}")

        # Show coordinator statistics
        coord_stats = results.get("coordinator_statistics", {})
        if coord_stats:
            print(f"\n📊 Coordinator Statistics:")
            print(f"   Total generations: {coord_stats.get('total_generations', 0)}")
            print(f"   Total batches processed: {coord_stats.get('total_batches', 0)}")

            suggestions = coord_stats.get('improvement_suggestions', [])
            if suggestions:
                print(f"\n💡 Improvement Suggestions:")
                for sugg in suggestions[:3]:
                    print(f"   - {sugg}")

        return True

    except Exception as e:
        print(f"\n❌ Evolution failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    print("🧬 EvoPrompt: Multi-Agent Collaborative Evolution")
    print("=" * 70)

    # Setup environment
    if not setup_environment():
        return 1

    # Check for data - prefer full dataset over demo
    data_dir = "./data/primevul_1percent_sample"
    if not os.path.exists(data_dir):
        data_dir = "./data/demo_primevul_1percent_sample"
        print(f"⚠️  Warning: Using small demo dataset ({data_dir})")
        print("   For better results, use the full 1% dataset")

    if not os.path.exists(data_dir):
        print("\n❌ No sample data found")
        print("   Please run data sampling first:")
        print("   uv run python scripts/ablations/demo_primevul_1percent.py")
        return 1

    print(f"✅ Using dataset: {data_dir}")

    # Run demo
    output_dir = "./outputs/multiagent_coevolution"
    success = run_multiagent_demo(data_dir, output_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
