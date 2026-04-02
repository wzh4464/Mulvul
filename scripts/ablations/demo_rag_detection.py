#!/usr/bin/env python3
"""Demo of RAG-enhanced three-layer detection.

Shows how retrieval-augmented generation improves vulnerability detection
by injecting similar examples into prompts.
"""

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from evoprompt.prompts.hierarchical_three_layer import ThreeLayerPromptFactory
from evoprompt.detectors.rag_three_layer_detector import RAGThreeLayerDetector
from evoprompt.rag.knowledge_base import KnowledgeBaseBuilder
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


def demonstrate_knowledge_base():
    """Demonstrate knowledge base creation."""
    print("\n📚 Creating Knowledge Base")
    print("=" * 70)

    kb = KnowledgeBaseBuilder.create_default_kb()

    stats = kb.statistics()
    print(f"✅ Knowledge base created:")
    print(f"   Total examples: {stats['total_examples']}")
    print(f"   Major categories: {stats['major_categories']}")
    print(f"   Middle categories: {stats['middle_categories']}")
    print(f"   CWE types: {stats['cwe_types']}")

    print("\n📊 Examples per major category:")
    for cat, count in stats['examples_per_major'].items():
        print(f"   {cat}: {count} examples")

    print("\n📊 Examples per middle category:")
    for cat, count in stats['examples_per_middle'].items():
        print(f"   {cat}: {count} examples")

    return kb


def test_rag_detection(llm_client, kb):
    """Test RAG-enhanced detection."""
    print("\n🔍 Testing RAG-Enhanced Detection")
    print("=" * 70)

    # Create prompt set
    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()

    # Create RAG detector
    detector = RAGThreeLayerDetector(
        prompt_set=prompt_set,
        llm_client=llm_client,
        knowledge_base=kb,
        use_scale_enhancement=False,
        retriever_type="lexical",
        top_k=2  # Retrieve 2 examples per layer
    )

    # Test code samples
    test_samples = [
        {
            "name": "Buffer Overflow",
            "code": """void copy_data(char* input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking
    printf("%s", buffer);
}""",
            "expected": {
                "layer1": "Memory",
                "layer2": "Buffer Overflow",
                "layer3": "CWE-120 or CWE-787"
            }
        },
        {
            "name": "SQL Injection",
            "code": """String query = "SELECT * FROM users WHERE id=" + userId;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);""",
            "expected": {
                "layer1": "Injection",
                "layer2": "SQL Injection",
                "layer3": "CWE-89"
            }
        },
        {
            "name": "Path Traversal",
            "code": """String filename = request.getParameter("file");
File f = new File("/uploads/" + filename);
FileInputStream fis = new FileInputStream(f);""",
            "expected": {
                "layer1": "Input",
                "layer2": "Path Traversal",
                "layer3": "CWE-22"
            }
        }
    ]

    for i, sample in enumerate(test_samples, 1):
        print(f"\n{'='*70}")
        print(f"Test {i}: {sample['name']}")
        print(f"{'='*70}")

        print("\n📝 Code:")
        print(sample['code'])

        print("\n🔍 Detecting with RAG...")
        start = time.time()

        try:
            predicted_cwe, details = detector.detect(sample['code'], return_intermediate=True)
            elapsed = time.time() - start

            print(f"\n✅ Detection complete ({elapsed:.1f}s)")

            # Show results
            print("\n📊 Results:")
            print(f"   Layer 1: {details.get('layer1', 'Unknown')}")
            print(f"   Layer 2: {details.get('layer2', 'Unknown')}")
            print(f"   Layer 3: {details.get('layer3', 'Unknown')}")
            print(f"\n🎯 Final: {predicted_cwe or 'Unknown'}")

            # Show retrieval info
            print("\n🔎 RAG Retrieval Info:")

            for layer_num in [1, 2, 3]:
                layer_key = f"layer{layer_num}_retrieval"
                if layer_key in details:
                    retrieval = details[layer_key]
                    print(f"\n   Layer {layer_num}:")
                    print(f"      Examples retrieved: {retrieval.get('num_examples', 0)}")
                    if retrieval.get('similarity_scores'):
                        scores = retrieval['similarity_scores']
                        print(f"      Similarity scores: {[f'{s:.3f}' for s in scores]}")
                    if retrieval.get('example_categories'):
                        cats = retrieval['example_categories']
                        print(f"      Example categories: {cats}")

            # Show expected
            print("\n💡 Expected:")
            print(f"   Layer 1: {sample['expected']['layer1']}")
            print(f"   Layer 2: {sample['expected']['layer2']}")
            print(f"   Layer 3: {sample['expected']['layer3']}")

            # Check correctness
            correct_l1 = details.get('layer1') == sample['expected']['layer1']
            correct_l2 = details.get('layer2') == sample['expected']['layer2']

            print("\n✔️  Correctness:")
            print(f"   Layer 1: {'✅' if correct_l1 else '❌'}")
            print(f"   Layer 2: {'✅' if correct_l2 else '❌'}")

        except Exception as e:
            print(f"\n❌ Detection failed: {e}")
            import traceback
            traceback.print_exc()

        # Wait between samples to avoid rate limiting
        if i < len(test_samples):
            time.sleep(1)


def compare_with_without_rag(llm_client, kb):
    """Compare detection with and without RAG."""
    print("\n⚖️  Comparing RAG vs Non-RAG Detection")
    print("=" * 70)

    from evoprompt.detectors.three_layer_detector import ThreeLayerDetector

    prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()

    # Without RAG
    detector_no_rag = ThreeLayerDetector(
        prompt_set=prompt_set,
        llm_client=llm_client,
        use_scale_enhancement=False
    )

    # With RAG
    detector_rag = RAGThreeLayerDetector(
        prompt_set=prompt_set,
        llm_client=llm_client,
        knowledge_base=kb,
        use_scale_enhancement=False,
        top_k=2
    )

    test_code = """char dest[10];
strcpy(dest, user_input);  // Overflow!"""

    print("\n📝 Test code:")
    print(test_code)

    print("\n🔍 Without RAG:")
    try:
        cwe1, details1 = detector_no_rag.detect(test_code)
        print(f"   Layer 1: {details1.get('layer1')}")
        print(f"   Layer 2: {details1.get('layer2')}")
        print(f"   Layer 3: {details1.get('layer3')}")
        print(f"   Final: {cwe1}")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n🔍 With RAG:")
    try:
        cwe2, details2 = detector_rag.detect(test_code)
        print(f"   Layer 1: {details2.get('layer1')}")
        print(f"   Layer 2: {details2.get('layer2')}")
        print(f"   Layer 3: {details2.get('layer3')}")
        print(f"   Final: {cwe2}")

        # Show retrieval
        if 'layer1_retrieval' in details2:
            r = details2['layer1_retrieval']
            print(f"   Retrieved {r.get('num_examples', 0)} examples at Layer 1")
    except Exception as e:
        print(f"   Error: {e}")


def show_rag_benefits():
    """Explain RAG benefits."""
    print("\n💡 RAG Benefits for Vulnerability Detection")
    print("=" * 70)

    print("""
RAG (Retrieval-Augmented Generation) enhances detection by:

1. **Example-Based Learning**
   - Shows LLM similar vulnerable code patterns
   - Helps recognize subtle variations of known vulnerabilities
   - Improves few-shot learning without fine-tuning

2. **Context-Aware Classification**
   - Retrieves category-specific examples at each layer
   - Narrows down to more relevant examples progressively
   - Reduces ambiguity in classification

3. **Knowledge Base Integration**
   - Leverages curated examples from all categories
   - Can be updated with new vulnerability patterns
   - No model retraining needed

4. **Interpretability**
   - Shows which examples influenced the decision
   - Similarity scores indicate confidence
   - Helps debug classification errors

Key Parameters:
   - top_k: Number of examples to retrieve (default: 2)
   - retriever_type: "lexical" (fast) or "embedding" (accurate)
   - knowledge_base: Can be built from dataset or manually curated
""")


def main():
    """Main entry point."""
    print("🏗️  RAG-Enhanced Three-Layer Detection Demo")
    print("=" * 70)

    if not setup_environment():
        return 1

    # Step 1: Create knowledge base
    kb = demonstrate_knowledge_base()

    # Option to save KB
    kb_path = "./outputs/knowledge_base.json"
    os.makedirs(os.path.dirname(kb_path), exist_ok=True)
    kb.save(kb_path)
    print(f"\n💾 Knowledge base saved to: {kb_path}")

    # Step 2: Test RAG detection
    llm_client = create_llm_client(llm_type=os.getenv("MODEL_NAME", "gpt-4"))

    print("\n" + "=" * 70)
    response = input("\nRun RAG detection tests? (y/n) [y]: ").strip().lower()
    if response in ['', 'y', 'yes']:
        test_rag_detection(llm_client, kb)
    else:
        print("⏭️  Skipped RAG detection tests")

    # Step 3: Compare with/without RAG
    print("\n" + "=" * 70)
    response = input("\nRun RAG comparison? (y/n) [n]: ").strip().lower()
    if response in ['y', 'yes']:
        compare_with_without_rag(llm_client, kb)
    else:
        print("⏭️  Skipped RAG comparison")

    # Step 4: Show benefits
    show_rag_benefits()

    print("\n" + "=" * 70)
    print("✨ Demo Complete!")
    print()
    print("Next Steps:")
    print("   1. Build knowledge base from your dataset")
    print("   2. Experiment with different top_k values")
    print("   3. Try embedding-based retrieval for better accuracy")
    print("   4. Integrate RAG into training pipeline")
    print()
    print("📚 Documentation:")
    print("   - THREE_LAYER_README.md (three-layer structure)")
    print("   - RAG_README.md (RAG integration - to be created)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
