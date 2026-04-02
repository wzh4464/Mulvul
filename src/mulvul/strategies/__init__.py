"""Detection strategy interface and factory."""

from __future__ import annotations

import os
from typing import List, Protocol, Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from mulvul.data.dataset import Sample


class DetectionStrategy(Protocol):
    """Interface for all detection strategies.

    Every mode (flat, hierarchical, mulvul, baseline, coevolution)
    implements this protocol so the evolution loop in main.py stays unchanged.
    """

    def predict_batch(
        self, prompt: str, samples: List[Sample], batch_idx: int
    ) -> List[str]:
        """Return predicted category for each sample."""
        ...

    def get_ground_truth(self, sample: Sample) -> str:
        """Return ground truth category for a sample."""
        ...


def create_strategy(mode: str, llm_client: Any, config: Dict[str, Any]) -> DetectionStrategy:
    """Factory: create the right strategy based on --mode flag."""
    if mode == "flat":
        from mulvul.strategies.flat import FlatStrategy
        return FlatStrategy(llm_client, config)
    if mode == "hierarchical":
        from mulvul.strategies.hierarchical import HierarchicalStrategy
        return HierarchicalStrategy(llm_client, config)
    if mode == "mulvul":
        allow_legacy = config.get("allow_legacy_mulvul", False) or os.getenv(
            "MULVUL_ENABLE_LEGACY_MODE", ""
        ).lower() in {"1", "true", "yes"}
        if not allow_legacy:
            raise ValueError(
                "Legacy mode 'mulvul' is disabled by default because its "
                "evolution interface ignores the evolving prompt. Use the "
                "mainline workflows instead, or re-enable it explicitly with "
                "--allow-legacy-mulvul / MULVUL_ENABLE_LEGACY_MODE=1."
            )
        from mulvul.strategies.mulvul_strategy import MulVulStrategy
        return MulVulStrategy(llm_client, config)
    if mode == "baseline":
        from mulvul.strategies.baseline import BaselineStrategy
        return BaselineStrategy(llm_client, config)
    if mode == "coevolution":
        from mulvul.strategies.coevolution_strategy import CoevolutionStrategy
        return CoevolutionStrategy(llm_client, config)
    raise ValueError(f"Unknown mode: {mode!r}. Choose from: flat, hierarchical, mulvul, baseline, coevolution")
