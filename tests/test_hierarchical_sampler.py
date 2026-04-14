import json

from mulvul.agents.hierarchical_sampler import HierarchicalSampler


def test_sampler_accepts_null_cve_desc(tmp_path):
    data_path = tmp_path / "samples.jsonl"
    records = [
        {
            "func": "def vulnerable(x):\n    value = x + 1\n    return value * 2\n" * 3,
            "target": 1,
            "cwe": ["CWE-79"],
            "cve_desc": None,
        },
        {
            "func": "def benign(x):\n    total = x + 1\n    return total\n" * 3,
            "target": 0,
            "cwe": [],
            "cve_desc": None,
        },
    ]
    with data_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")

    sampler = HierarchicalSampler(str(data_path))

    assert len(sampler.by_cwe["CWE-79"]) == 1
    assert sampler.by_cwe["CWE-79"][0]["description"] == ""
