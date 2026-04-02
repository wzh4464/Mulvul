#!/usr/bin/env python3
"""快速训练测试 - 验证训练功能"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

print("🧪 Quick Training Test", flush=True)
print("="*70, flush=True)

# Test imports
print("\n✅ Step 1: Testing imports...", flush=True)
try:
    from mulvul.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
    from mulvul.multiagent.agents import create_detection_agent, create_meta_agent
    from mulvul.multiagent.coordinator import MultiAgentCoordinator, CoordinatorConfig
    from mulvul.algorithms.coevolution import CoevolutionaryAlgorithm
    from mulvul.data.dataset import PrimevulDataset
    from mulvul.llm.client import load_env_vars
    print("   ✅ All imports successful", flush=True)
except Exception as e:
    print(f"   ❌ Import failed: {e}", flush=True)
    sys.exit(1)

# Load environment
print("\n✅ Step 2: Loading environment...", flush=True)
load_env_vars()
print(f"   Model: {os.getenv('MODEL_NAME', 'gpt-4')}", flush=True)

# Create agents
print("\n✅ Step 3: Creating agents...", flush=True)
try:
    detection_agent = create_detection_agent(model_name=os.getenv("MODEL_NAME", "gpt-4"))
    meta_agent = create_meta_agent(model_name=os.getenv("META_MODEL_NAME", "claude-4.5"))
    print("   ✅ Agents created", flush=True)
except Exception as e:
    print(f"   ❌ Agent creation failed: {e}", flush=True)
    sys.exit(1)

# Create coordinator
print("\n✅ Step 4: Creating coordinator...", flush=True)
try:
    coordinator_config = CoordinatorConfig(batch_size=5)
    coordinator = MultiAgentCoordinator(
        detection_agent=detection_agent,
        meta_agent=meta_agent,
        config=coordinator_config
    )
    print("   ✅ Coordinator created", flush=True)
except Exception as e:
    print(f"   ❌ Coordinator creation failed: {e}", flush=True)
    sys.exit(1)

# Load small dataset
print("\n✅ Step 5: Loading dataset...", flush=True)
try:
    dataset = PrimevulDataset("./data/primevul_1percent_sample/train.txt", "train")
    print(f"   ✅ Loaded {len(dataset)} samples", flush=True)
except Exception as e:
    print(f"   ❌ Dataset loading failed: {e}", flush=True)
    sys.exit(1)

# Create algorithm
print("\n✅ Step 6: Creating algorithm...", flush=True)
try:
    config = {
        "population_size": 2,
        "max_generations": 1,
        "elite_size": 1,
        "mutation_rate": 0.3,
    }
    algorithm = CoevolutionaryAlgorithm(
        config=config,
        coordinator=coordinator,
        dataset=dataset
    )
    print("   ✅ Algorithm created", flush=True)
except Exception as e:
    print(f"   ❌ Algorithm creation failed: {e}", flush=True)
    sys.exit(1)

# Create initial prompt
print("\n✅ Step 7: Creating initial prompt...", flush=True)
try:
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    initial_prompts = [prompt_set.layer1_prompt]
    print(f"   ✅ Initial prompt length: {len(initial_prompts[0])} chars", flush=True)
except Exception as e:
    print(f"   ❌ Prompt creation failed: {e}", flush=True)
    sys.exit(1)

# Run evolution
print("\n✅ Step 8: Running evolution (1 generation, 2 population)...", flush=True)
print("   This will take a few minutes due to LLM API calls...", flush=True)
try:
    best_individual = algorithm.evolve(initial_prompts=initial_prompts)
    print(f"\n   ✅ Evolution completed!", flush=True)
    print(f"   Best fitness: {best_individual.fitness:.4f}", flush=True)
except Exception as e:
    print(f"   ❌ Evolution failed: {e}", flush=True)
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "="*70, flush=True)
print("🎉 All tests passed! Training system is working!", flush=True)
