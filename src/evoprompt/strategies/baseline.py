"""Baseline zero-shot classification strategy.

Simplest strategy: single-pass LLM classification with no evolution.
Functionally identical to FlatStrategy but explicitly labeled as baseline
so experiment logs and comparisons are unambiguous.
"""

from __future__ import annotations

from typing import Any, Dict, List

from evoprompt.data.cwe_categories import canonicalize_category, map_cwe_to_major
from evoprompt.data.dataset import Sample
from evoprompt.utils.text import safe_format


class BaselineStrategy:
    """Zero-shot baseline: one prompt, one LLM call per sample, no evolution."""

    def __init__(self, llm_client: Any, config: Dict[str, Any] | None = None):
        self.llm_client = llm_client
        self.config = config or {}

    def get_ground_truth(self, sample: Sample) -> str:
        ground_truth_binary = int(sample.target)
        cwe_codes = sample.metadata.get("cwe", [])
        if ground_truth_binary == 1 and cwe_codes:
            return map_cwe_to_major(cwe_codes)
        return "Benign"

    def predict_batch(
        self, prompt: str, samples: List[Sample], batch_idx: int
    ) -> List[str]:
        queries = [safe_format(prompt, input=s.input_text) for s in samples]

        print(f"      [baseline] batch predict {len(queries)} samples...")
        responses = self.llm_client.batch_generate(
            queries,
            temperature=0.1,
            max_tokens=20,
            batch_size=min(8, len(queries)),
            concurrent=True,
        )

        predictions: List[str] = []
        for idx, response in enumerate(responses):
            if response == "error":
                predictions.append("Other")
                continue

            cat = canonicalize_category(response)

            if batch_idx == 0 and idx < 3:
                print(f"        [baseline] response {idx+1}: '{response[:100]}...'")
                print(f"        [baseline] parsed: '{cat}'")

            if cat is None:
                lower = response.lower()
                cat = canonicalize_category(lower)
                if cat is None:
                    if any(p in lower for p in (
                        "benign", "no vuln", "no security issue",
                        "not vulnerable", "safe", "secure code",
                    )):
                        cat = "Benign"
                    else:
                        cat = "Other"
                if batch_idx == 0 and idx < 3:
                    print(f"        [baseline] fallback: '{cat}'")

            predictions.append(cat)

        return predictions
