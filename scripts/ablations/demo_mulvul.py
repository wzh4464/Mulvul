#!/usr/bin/env python3
"""Demo script for MulVul multi-agent vulnerability detection.

Tests the complete Router-Detector-Aggregator pipeline.
"""

import sys
sys.path.insert(0, "src")

from evoprompt.llm.client import create_llm_client, load_env_vars
from evoprompt.agents import MulVulDetector, DetectionResult


def demo_mulvul():
    """Demo MulVul detection on sample code."""

    load_env_vars()

    print("=" * 70)
    print("🔥 MulVul Multi-Agent Vulnerability Detection Demo")
    print("=" * 70)

    # Create MulVul detector
    llm_client = create_llm_client()
    detector = MulVulDetector.create_default(
        llm_client=llm_client,
        retriever=None,  # No RAG for demo
        max_agents=3,
        parallel=True,
        adaptive=True,
    )

    # Test cases
    test_cases = [
        {
            "name": "Buffer Overflow",
            "expected": "Memory",
            "code": """
void vulnerable_function(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // No bounds checking
    printf("Input: %s\\n", buffer);
}
""",
        },
        {
            "name": "SQL Injection",
            "expected": "Injection",
            "code": """
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()
""",
        },
        {
            "name": "Path Traversal",
            "expected": "Input",
            "code": """
def read_file(filename):
    path = "/var/data/" + filename
    with open(path, 'r') as f:
        return f.read()
""",
        },
        {
            "name": "Benign Code",
            "expected": "Benign",
            "code": """
def add_numbers(a, b):
    return a + b

def main():
    result = add_numbers(5, 3)
    print(f"Result: {result}")
""",
        },
    ]

    print("\n📊 Running detection on test cases...\n")

    results = []
    for i, test in enumerate(test_cases, 1):
        print(f"\n{'='*60}")
        print(f"Test {i}: {test['name']}")
        print(f"Expected Category: {test['expected']}")
        print(f"{'='*60}")

        # Run detection with details
        details = detector.detect_with_details(test["code"])

        # Print routing info
        print(f"\n🔀 Router Agent:")
        print(f"   Ranked categories: {details['routing']['ranked']}")
        print(f"   Selected detector categories: {details['routing']['selected']}")

        # Print detector results
        print(f"\n🔍 Detector Results:")
        for det in details["detectors"]:
            print(f"   [{det['category']}] {det['prediction']} (conf: {det['confidence']:.2f})")
            if det['evidence']:
                print(f"      Evidence: {det['evidence'][:80]}...")

        # Print final result
        final = details["final"]
        print(f"\n✅ Final Prediction:")
        print(f"   Prediction: {final['prediction']}")
        print(f"   Confidence: {final['confidence']:.2f}")
        print(f"   Category: {final['category']}")
        if final['evidence']:
            print(f"   Evidence: {final['evidence'][:100]}...")

        # Check correctness
        is_correct = (
            final['category'] == test['expected'] or
            (test['expected'] == "Benign" and final['prediction'] == "Benign")
        )
        status = "✅ CORRECT" if is_correct else "❌ WRONG"
        print(f"\n   {status}")

        results.append({
            "name": test["name"],
            "expected": test["expected"],
            "predicted": final["category"],
            "correct": is_correct,
        })

    # Summary
    print("\n" + "=" * 70)
    print("📊 Summary")
    print("=" * 70)

    correct = sum(1 for r in results if r["correct"])
    total = len(results)
    print(f"Accuracy: {correct}/{total} ({correct/total:.1%})")

    print("\nDetailed Results:")
    for r in results:
        status = "✅" if r["correct"] else "❌"
        print(f"  {status} {r['name']}: expected={r['expected']}, predicted={r['predicted']}")


if __name__ == "__main__":
    demo_mulvul()
