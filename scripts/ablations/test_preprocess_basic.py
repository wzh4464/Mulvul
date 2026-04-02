#!/usr/bin/env python3
"""
Basic test for PrimeVul to comment4vul format conversion (without NL AST processing).

This test validates the data format conversion without requiring parserTool dependency.
"""

import json
import jsonlines
from pathlib import Path
import sys

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent))

from preprocess_primevul_comment4vul import convert_primevul_to_comment4vul_format


def test_format_conversion():
    """Test PrimeVul to comment4vul format conversion."""
    print("Testing PrimeVul to comment4vul format conversion...")

    # Sample PrimeVul record
    primevul_sample = {
        "idx": 210536,
        "project": "linux",
        "target": 1,
        "func": "static int vt_disallocate(unsigned int vc_num)\n{\n\tif (vt_busy(vc_num))\n\t\tret = -EBUSY;\n\treturn ret;\n}",
        "cwe": ["CWE-416"],
        "cve": "CVE-2020-36557"
    }

    # Convert to comment4vul format
    c4v_record = convert_primevul_to_comment4vul_format(primevul_sample)

    # Verify required fields
    assert "idx" in c4v_record, "Missing idx field"
    assert "target" in c4v_record, "Missing target field"
    assert "func" in c4v_record, "Missing func field"
    assert "choices" in c4v_record, "Missing choices field"

    # Verify values
    assert c4v_record["idx"] == 210536, "Incorrect idx"
    assert c4v_record["target"] == 1, "Incorrect target"
    assert c4v_record["func"] == primevul_sample["func"], "Incorrect func"

    print("✓ Format conversion test passed!")
    print(f"  idx: {c4v_record['idx']}")
    print(f"  target: {c4v_record['target']}")
    print(f"  func length: {len(c4v_record['func'])} chars")
    print(f"  choices length: {len(c4v_record['choices'])} chars")

    return True


def test_load_real_data():
    """Test loading real PrimeVul data."""
    print("\nTesting real PrimeVul data loading...")

    # Try to load real sample file
    sample_paths = [
        Path("data/primevul_1percent_sample/train_sample.jsonl"),
        Path("data/primevul/primevul/train_sample.jsonl"),
        Path("data/demo_primevul_1percent_sample/train_sample.jsonl"),
    ]

    sample_path = None
    for path in sample_paths:
        if path.exists():
            sample_path = path
            break

    if sample_path is None:
        print("⚠ No sample data found, skipping real data test")
        return True

    print(f"  Loading from: {sample_path}")

    # Load first 3 records
    records = []
    with jsonlines.open(sample_path) as reader:
        for i, record in enumerate(reader):
            if i >= 3:
                break
            records.append(record)

    print(f"✓ Loaded {len(records)} records")

    # Convert each record
    for i, record in enumerate(records):
        c4v_record = convert_primevul_to_comment4vul_format(record)
        print(f"  Record {i}: idx={c4v_record['idx']}, target={c4v_record['target']}")

    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("PrimeVul Preprocessing Basic Tests")
    print("=" * 60)

    try:
        # Test format conversion
        test_format_conversion()

        # Test real data loading
        test_load_real_data()

        print("\n" + "=" * 60)
        print("✓ All basic tests passed!")
        print("=" * 60)
        print("\nNote: Full NL AST processing requires parserTool dependency.")
        print("See docs/primevul_comment4vul_integration.md for setup instructions.")

    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
