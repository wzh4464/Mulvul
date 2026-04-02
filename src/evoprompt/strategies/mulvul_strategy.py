"""MulVul multi-agent detection strategy.

Wraps the Router -> parallel Detectors -> Aggregator pipeline from
``evoprompt.agents.mulvul.MulVulDetector`` behind the ``DetectionStrategy``
protocol so the evolution loop in main.py can use it transparently.
"""

from __future__ import annotations

from typing import Any, Dict, List

from evoprompt.agents.mulvul import MulVulDetector
from evoprompt.data.cwe_categories import (
    CWE_MAJOR_CATEGORIES,
    canonicalize_category,
    map_cwe_to_major,
)
from evoprompt.data.dataset import Sample

# Maps the coarse agent categories (used by RouterAgent / DetectorAgent)
# to the fine-grained CWE_MAJOR_CATEGORIES labels used by the evolution loop.
_AGENT_CAT_TO_MAJOR: Dict[str, str] = {
    "Memory": "Buffer Errors",          # default; refined below via CWE
    "Injection": "Injection",
    "Logic": "Concurrency Issues",      # default; refined below via CWE
    "Input": "Path Traversal",          # default; refined below via CWE
    "Crypto": "Cryptography Issues",
    "Benign": "Benign",
}


def _result_to_label(result) -> str:
    """Convert a DetectionResult to a CWE_MAJOR_CATEGORIES label.

    Resolution order:
    1. If the result carries a CWE id (e.g. "CWE-416"), map it via
       ``canonicalize_category`` which knows CWE -> major category.
    2. If the prediction text itself can be canonicalized, use that.
    3. Fall back through the coarse agent-category mapping.
    4. Ultimate fallback: "Other".
    """
    # 1. Try the CWE field
    if result.cwe:
        cat = canonicalize_category(result.cwe)
        if cat and cat in CWE_MAJOR_CATEGORIES:
            return cat

    # 2. Try the prediction text (may be "CWE-120", "Buffer Errors", etc.)
    if result.prediction:
        cat = canonicalize_category(result.prediction)
        if cat and cat in CWE_MAJOR_CATEGORIES:
            return cat

    # 3. Coarse agent-category mapping
    if result.category in _AGENT_CAT_TO_MAJOR:
        return _AGENT_CAT_TO_MAJOR[result.category]

    return "Other"


class MulVulStrategy:
    """Multi-agent strategy: Router -> Detectors -> Aggregator.

    Each sample is run through the full MulVulDetector pipeline.  The
    aggregated ``DetectionResult`` is mapped to a ``CWE_MAJOR_CATEGORIES``
    label so it is compatible with the evolution loop's scoring.
    """

    def __init__(self, llm_client: Any, config: Dict[str, Any] | None = None):
        self.llm_client = llm_client
        self.config = config or {}

        max_agents = self.config.get("max_agents", self.config.get("k", 3))
        parallel = self.config.get("parallel", True)
        adaptive_agents = self.config.get("adaptive_agents", True)

        self.detector = MulVulDetector.create_default(
            llm_client=llm_client,
            retriever=self.config.get("retriever"),
            max_agents=max_agents,
            parallel=parallel,
            adaptive=adaptive_agents,
            min_agents=self.config.get("min_agents", 1),
            routing_confidence_threshold=self.config.get(
                "routing_confidence_threshold", 0.2
            ),
            routing_relative_threshold=self.config.get(
                "routing_relative_threshold", 0.6
            ),
            benign_short_circuit_threshold=self.config.get(
                "benign_short_circuit_threshold", 0.8
            ),
        )

    # ------------------------------------------------------------------
    # DetectionStrategy protocol
    # ------------------------------------------------------------------

    def get_ground_truth(self, sample: Sample) -> str:
        ground_truth_binary = int(sample.target)
        cwe_codes = sample.metadata.get("cwe", [])
        if ground_truth_binary == 1 and cwe_codes:
            return map_cwe_to_major(cwe_codes)
        return "Benign"

    def predict_batch(
        self, prompt: str, samples: List[Sample], batch_idx: int
    ) -> List[str]:
        """Run MulVulDetector on each sample and return category labels.

        ``prompt`` is accepted for interface compatibility but is not used
        directly -- the Router and Detector agents carry their own prompts.
        """
        predictions: List[str] = []

        print(f"      MulVul: detecting {len(samples)} samples (batch {batch_idx})...")

        for idx, sample in enumerate(samples):
            try:
                result = self.detector.detect(sample.input_text)
                label = _result_to_label(result)

                if batch_idx == 0 and idx < 3:
                    print(
                        f"        [{idx+1}] prediction={result.prediction!r} "
                        f"cwe={result.cwe!r} category={result.category!r} "
                        f"-> {label}"
                    )

                predictions.append(label)

            except Exception as e:
                if batch_idx == 0 and idx < 3:
                    print(f"        [{idx+1}] error: {e}")
                predictions.append("Other")

        return predictions
