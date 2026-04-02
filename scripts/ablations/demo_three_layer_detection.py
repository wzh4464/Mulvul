#!/usr/bin/env python3
"""
Three-Layer Hierarchical Detection Demo

Architecture:
1. Code → (Optional) Scale Enhancement
2. Layer 1: Major Category (Memory/Injection/Logic/Input/Crypto/Benign)
3. Layer 2: Middle Category (Buffer Overflow/SQL Injection/etc.)
4. Layer 3: Specific CWE (CWE-120/CWE-89/etc.)

All prompts are trainable using Multi-agent evolution.
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.prompts.hierarchical_three_layer import (
    ThreeLayerPromptSet,
    ThreeLayerPromptFactory,
    MajorCategory,
    MiddleCategory,
    get_full_path,
)
from evoprompt.detectors.three_layer_detector import (
    ThreeLayerDetector,
    ThreeLayerEvaluator,
)
from evoprompt.data.dataset import PrimevulDataset
from evoprompt.llm.client import load_env_vars, create_llm_client


def setup_environment():
    """Setup environment."""
    load_env_vars()

    api_key = os.getenv("API_KEY")
    if not api_key:
        print("❌ API_KEY not found")
        return False

    print("✅ Environment configured:")
    print(f"   Model: {os.getenv('MODEL_NAME', 'gpt-4')}")

    return True


def demonstrate_three_layer_structure():
    """Demonstrate the three-layer structure."""
    print("\n🏗️  Three-Layer Hierarchical Structure")
    print("=" * 70)

    # Show hierarchy
    print("\n📊 Category Hierarchy:")
    print(f"\nLayer 1 (Major Categories): {len(list(MajorCategory))} categories")
    for major in MajorCategory:
        print(f"   - {major.value}")

    print(f"\nLayer 2 (Middle Categories): {len(list(MiddleCategory))} categories")
    from evoprompt.prompts.hierarchical_three_layer import MAJOR_TO_MIDDLE

    for major, middles in MAJOR_TO_MIDDLE.items():
        print(f"   {major.value}:")
        for middle in middles:
            print(f"      - {middle.value}")

    print(f"\nLayer 3 (CWE IDs): Mapped from middle categories")
    from evoprompt.prompts.hierarchical_three_layer import MIDDLE_TO_CWE

    # Show a few examples
    examples = list(MIDDLE_TO_CWE.items())[:5]
    for middle, cwes in examples:
        print(f"   {middle.value}: {', '.join(cwes)}")
    print("   ...")

    # Show prompt counts
    print(f"\n📝 Prompt Configuration:")
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    counts = prompt_set.count_prompts()
    print(f"   Layer 1 prompts: {counts['layer1']} (Major category routing)")
    print(f"   Layer 2 prompts: {counts['layer2']} (Middle category per major)")
    print(f"   Layer 3 prompts: {counts['layer3']} (CWE-specific)")
    print(f"   Total prompts: {counts['total']}")
    print(f"\n   All {counts['total']} prompts are trainable! 🎯")


def test_single_detection(llm_client):
    """Test detection on a single code sample."""
    print("\n🧪 Testing Single Detection")
    print("=" * 70)

    # Create prompt set
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()

    # Create detector
    detector = ThreeLayerDetector(
        prompt_set=prompt_set,
        llm_client=llm_client,
        use_scale_enhancement=False  # Disable for speed
    )

    # Test code sample
    test_code = """
void process_input(char* user_input) {
    char buffer[100];
    strcpy(buffer, user_input);  // Unsafe!
    printf("%s", buffer);
}
"""

    print("📝 Test Code:")
    print(test_code)
    print()

    print("🔍 Detecting...")
    start = time.time()

    try:
        predicted_cwe, details = detector.detect(test_code, return_intermediate=True)
        elapsed = time.time() - start

        print(f"✅ Detection complete ({elapsed:.1f}s)")
        print()
        print("📊 Results:")
        print(f"   Layer 1 (Major):  {details.get('layer1', 'Unknown')}")
        print(f"   Layer 2 (Middle): {details.get('layer2', 'Unknown')}")
        print(f"   Layer 3 (CWE):    {details.get('layer3', 'Unknown')}")
        print()
        print(f"🎯 Final Prediction: {predicted_cwe or 'Unknown'}")

        # Show expected path
        print()
        print("💡 Expected Path:")
        print("   Layer 1: Memory")
        print("   Layer 2: Buffer Overflow")
        print("   Layer 3: CWE-120 or CWE-787")

        return True

    except Exception as e:
        print(f"❌ Detection failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def evaluate_on_dataset(llm_client, data_dir: str, max_samples: int = 50):
    """Evaluate three-layer detector on dataset."""
    print("\n📊 Evaluating on Dataset")
    print("=" * 70)

    # Load dataset
    dev_file = Path(data_dir) / "dev.txt"
    if not dev_file.exists():
        print(f"❌ Dataset not found: {dev_file}")
        return False

    dataset = PrimevulDataset(str(dev_file), split="dev")
    print(f"   ✅ Loaded {len(dataset)} samples")
    print(f"   🔍 Evaluating on {min(max_samples, len(dataset))} samples")

    # Create detector
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    detector = ThreeLayerDetector(
        prompt_set=prompt_set,
        llm_client=llm_client,
        use_scale_enhancement=False
    )

    # Create evaluator
    evaluator = ThreeLayerEvaluator(detector, dataset)

    # Evaluate
    print("\n🔬 Running evaluation...")
    start = time.time()

    try:
        metrics = evaluator.evaluate(sample_size=max_samples)
        elapsed = time.time() - start

        print(f"✅ Evaluation complete ({elapsed:.1f}s)")
        print()
        print("📈 Results:")
        print(f"   Total samples:     {metrics['total_samples']}")
        print(f"   Layer 1 accuracy:  {metrics['layer1_accuracy']:.1%}")
        print(f"   Layer 2 accuracy:  {metrics['layer2_accuracy']:.1%}")
        print(f"   Layer 3 accuracy:  {metrics['layer3_accuracy']:.1%}")
        print(f"   Full path accuracy: {metrics['full_path_accuracy']:.1%}")
        print()
        print("💡 Interpretation:")
        print("   - Layer 1: Can we correctly identify major category?")
        print("   - Layer 2: Given correct major, can we find middle category?")
        print("   - Layer 3: Given correct middle, can we find specific CWE?")
        print("   - Full path: All three layers correct?")

        return True

    except Exception as e:
        print(f"❌ Evaluation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def show_training_strategy():
    """Explain how to train the three-layer system."""
    print("\n🎓 Training Strategy")
    print("=" * 70)

    print("""
Three-Layer Prompt Training:

1. **Independent Training** (Recommended for initial tuning)
   - Train Layer 1 prompt first (major category)
   - Train Layer 2 prompts (one per major category)
   - Train Layer 3 prompts (one per middle category)

2. **Joint Training** (For final optimization)
   - Train all prompts together
   - Use Multi-agent Meta-optimizer
   - Optimize based on full-path accuracy

3. **Curriculum Training** (For best results)
   - Stage 1: Train Layer 1 until 80%+ accuracy
   - Stage 2: Fix Layer 1, train Layer 2
   - Stage 3: Fix Layer 1+2, train Layer 3
   - Stage 4: Fine-tune all layers together

Training Tools:
   - Meta Agent (Claude 4.5): Analyzes errors, suggests improvements
   - Detection Agent (GPT-4): Tests prompt performance
   - Coordinator: Manages batch evaluation and feedback

Metrics to Track:
   - Per-layer accuracy
   - Error propagation (how many errors from Layer 1 affect Layer 2?)
   - Category-specific performance (which categories are hard?)

Next Steps:
   1. Run this demo to establish baseline
   2. Identify weak layers/categories
   3. Use Meta-agent to improve specific prompts
   4. Iterate until satisfactory performance
""")


def main():
    """Main entry point."""
    print("🏗️  Three-Layer Hierarchical Detection System")
    print("=" * 70)

    if not setup_environment():
        return 1

    # Step 1: Show structure
    demonstrate_three_layer_structure()

    # Step 2: Test single detection
    print("\nStep 1: Testing single detection...")
    llm_client = create_llm_client(llm_type=os.getenv("MODEL_NAME", "gpt-4"))

    if not test_single_detection(llm_client):
        print("⚠️  Single detection test failed")

    # Step 3: Evaluate on dataset (optional)
    data_dir = "./data/primevul_1percent_sample"
    if os.path.exists(data_dir):
        print("\nStep 2: Evaluating on dataset...")

        response = input("\nRun dataset evaluation? (y/n) [n]: ").strip().lower()
        if response == 'y':
            evaluate_on_dataset(llm_client, data_dir, max_samples=20)
        else:
            print("⏭️  Skipped dataset evaluation")
    else:
        print(f"\n⚠️  Dataset not found: {data_dir}")
        print("   Skipping dataset evaluation")

    # Step 4: Show training strategy
    show_training_strategy()

    print("\n" + "=" * 70)
    print("✨ Demo Complete!")
    print()
    print("Next Steps:")
    print("   1. Review the three-layer structure above")
    print("   2. Test on your own code samples")
    print("   3. Use Multi-agent training to optimize prompts")
    print()
    print("📚 Documentation:")
    print("   - THREE_LAYER_README.md (to be created)")
    print("   - MULTIAGENT_README.md (multi-agent training)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
