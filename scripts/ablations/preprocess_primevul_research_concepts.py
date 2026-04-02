import json
import os
from collections import defaultdict
import argparse
from typing import List

# Research Concepts mapping
RESEARCH_CONCEPTS = {
    0: "No Vulnerability",
    1: "Improper Access Control",
    2: "Improper Interaction Between Multiple Correctly-Behaving Entities",
    3: "Improper Control of a Resource Through its Lifetime",
    4: "Incorrect Calculation",
    5: "Insufficient Control Flow Management",
    6: "Protection Mechanism Failure",
    7: "Incorrect Comparison",
    8: "Improper Check or Handling of Exceptional Conditions",
    9: "Improper Neutralization",
    10: "Improper Adherence to Coding Standards",
}

SPECIFIC_CWE_TO_CATEGORY = {
    "CWE-22": 1, "CWE-23": 1, "CWE-36": 1, "CWE-284": 1, "CWE-285": 1, "CWE-862": 1, "CWE-863": 1,
    "CWE-362": 2, "CWE-367": 2, "CWE-364": 2, "CWE-435": 2,
    "CWE-119": 3, "CWE-120": 3, "CWE-121": 3, "CWE-122": 3, "CWE-125": 3, "CWE-126": 3, "CWE-127": 3,
    "CWE-131": 3, "CWE-401": 3, "CWE-415": 3, "CWE-416": 3, "CWE-476": 3, "CWE-664": 3, "CWE-787": 3,
    "CWE-190": 4, "CWE-191": 4, "CWE-192": 4, "CWE-193": 4, "CWE-369": 4, "CWE-682": 4,
    "CWE-691": 5, "CWE-670": 5, "CWE-617": 5,
    "CWE-693": 6, "CWE-311": 6, "CWE-312": 6, "CWE-327": 6, "CWE-330": 6,
    "CWE-697": 7, "CWE-595": 7, "CWE-486": 7,
    "CWE-252": 8, "CWE-248": 8, "CWE-703": 8, "CWE-754": 8, "CWE-755": 8,
    "CWE-20": 9, "CWE-74": 9, "CWE-78": 9, "CWE-79": 9, "CWE-89": 9, "CWE-94": 9, "CWE-707": 9, "CWE-116": 9,
    "CWE-710": 10, "CWE-561": 10, "CWE-563": 10,
}


def normalize_cwe_id(cwe: str) -> str:
    cwe = str(cwe).strip()
    if cwe.startswith("CWE-"):
        return cwe
    if cwe.isdigit():
        return f"CWE-{int(cwe)}"
    return cwe


def map_cwe_to_category(cwe_id) -> int:
    if isinstance(cwe_id, list):
        for c in cwe_id:
            cat = SPECIFIC_CWE_TO_CATEGORY.get(normalize_cwe_id(c), 0)
            if cat != 0:
                return cat
        return 0
    if isinstance(cwe_id, int):
        cwe_id = f"CWE-{cwe_id}"
    else:
        cwe_id = normalize_cwe_id(cwe_id)
    return SPECIFIC_CWE_TO_CATEGORY.get(cwe_id, 0)


def process_primevul_dataset(input_file: str) -> List[dict]:
    processed = []
    stats = defaultdict(int)
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            data = json.loads(line.strip())
            cwe_id = data.get("cwe", []) or data.get("cwe_id")
            original_label = data.get("target", 0)
            if original_label == 0:
                concept = 0
            else:
                concept = map_cwe_to_category(cwe_id)
            data["research_concept"] = concept
            data["research_concept_name"] = RESEARCH_CONCEPTS[concept]
            processed.append(data)
            stats[concept] += 1
    print("Research Concept Distribution:")
    for cid in sorted(stats.keys()):
        print(f"  {cid}: {RESEARCH_CONCEPTS[cid]} - {stats[cid]} samples")
    return processed


def write_jsonl(items: List[dict], path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for obj in items:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def create_category_files(processed: List[dict], out_dir: str):
    by_cat = defaultdict(list)
    for d in processed:
        by_cat[d["research_concept"]].append(d)
    os.makedirs(out_dir, exist_ok=True)
    for cid, samples in by_cat.items():
        if cid == 0:
            continue
        name = RESEARCH_CONCEPTS[cid].replace(" ", "_").lower()
        path = os.path.join(out_dir, f"category_{cid}_{name}.jsonl")
        write_jsonl(samples, path)
        print(f"Created {path} with {len(samples)} samples")


def create_balanced_splits(processed: List[dict], out_dir: str, samples_per_category: int = 1000):
    import random
    os.makedirs(out_dir, exist_ok=True)
    by_cat = defaultdict(list)
    for d in processed:
        by_cat[d["research_concept"]].append(d)
    train, valid, test = [], [], []
    for cid in range(11):
        samples = by_cat[cid]
        if not samples:
            continue
        random.shuffle(samples)
        total_needed = min(samples_per_category, len(samples))
        t = int(total_needed * 0.7)
        v = int(total_needed * 0.15)
        u = total_needed - t - v
        train.extend(samples[:t])
        valid.extend(samples[t:t+v])
        test.extend(samples[t+v:t+v+u])
    random.shuffle(train); random.shuffle(valid); random.shuffle(test)
    write_jsonl(train, os.path.join(out_dir, "balanced_train.jsonl"))
    write_jsonl(valid, os.path.join(out_dir, "balanced_valid.jsonl"))
    write_jsonl(test, os.path.join(out_dir, "balanced_test.jsonl"))
    print(f"Created balanced splits at {out_dir}")


def main():
    parser = argparse.ArgumentParser(description="Map PrimeVul CWEs to Research Concepts")
    parser.add_argument("--input", required=True, help="Input PrimeVul JSONL file")
    parser.add_argument("--output_dir", required=True, help="Output directory")
    parser.add_argument("--samples_per_category", type=int, default=1000, help="Max samples per category for balanced dataset")
    args = parser.parse_args()
    processed = process_primevul_dataset(args.input)
    processed_file = os.path.join(args.output_dir, "primevul_with_research_concepts.jsonl")
    write_jsonl(processed, processed_file)
    create_category_files(processed, os.path.join(args.output_dir, "by_category"))
    create_balanced_splits(processed, os.path.join(args.output_dir, "balanced"), args.samples_per_category)
    print("Dataset processing completed!")


if __name__ == "__main__":
    main()