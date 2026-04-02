"""Detection strategy interface and factory."""

from __future__ import annotations

from typing import List, Protocol, Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from evoprompt.data.dataset import Sample


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
        from evoprompt.strategies.flat import FlatStrategy
        return FlatStrategy(llm_client, config)
    if mode == "hierarchical":
        from evoprompt.strategies.hierarchical import HierarchicalStrategy
        return HierarchicalStrategy(llm_client, config)
    if mode == "mulvul":
        from evoprompt.strategies.mulvul_strategy import MulVulStrategy
        return MulVulStrategy(llm_client, config)
    if mode == "baseline":
        from evoprompt.strategies.baseline import BaselineStrategy
        return BaselineStrategy(llm_client, config)
    if mode == "coevolution":
        from evoprompt.strategies.coevolution_strategy import CoevolutionStrategy
        return CoevolutionStrategy(llm_client, config)
    raise ValueError(f"Unknown mode: {mode!r}. Choose from: flat, hierarchical, mulvul, baseline, coevolution")
