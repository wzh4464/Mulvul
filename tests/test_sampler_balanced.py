import json

from evoprompt.data.sampler import BalancedSampler


def _write_jsonl(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for item in items:
            f.write(json.dumps(item) + "\n")


def test_sample_primevul_balanced_by_major(tmp_path):
    data = [
        {"func": "void benign_a() {}", "target": 0, "cwe": []},
        {"func": "void benign_b() {}", "target": 0, "cwe": []},
        {"func": "void buf() { char b[8]; b[20]=0; }", "target": 1, "cwe": ["CWE-120"]},
        {"func": "void inj() { system(user); }", "target": 1, "cwe": ["CWE-89"]},
        {"func": "void inj2() { printf(user); }", "target": 1, "cwe": ["CWE-79"]},
    ]

    data_file = tmp_path / "primevul.jsonl"
    _write_jsonl(data_file, data)

    sampler = BalancedSampler(seed=123)
    sampled, stats = sampler.sample_primevul_balanced(
        str(data_file), sample_ratio=1.0, balance_mode="major"
    )

    labels = {item["_balance_label"] for item in sampled}
    assert labels == {"Benign", "Buffer Errors", "Injection"}

    counts = {label: stats[f"sampled_{label}"] for label in labels}
    assert len(set(counts.values())) == 1  # balanced across labels
