"""Ablation presets layered on top of the main router-detector workflow."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List


@dataclass
class AblationConfig:
    """Optional extensions on top of the mainline workflow."""

    use_retrieval: bool = False
    parallel_scoring: bool = False
    major_top_k: int = 1
    middle_top_k: int = 1
    decision_threshold: float = 0.5


SUPPORTED_ABLATIONS = {
    "rag": "Inject retrieval evidence into each stage prompt.",
    "parallel": "Score same-stage category prompts in parallel.",
    "topk-router": "Route top-2 majors and top-2 middles before choosing a path.",
}


def apply_ablation_presets(
    names: Iterable[str],
    base: AblationConfig | None = None,
) -> AblationConfig:
    """Apply named ablation presets to a baseline config."""

    config = base or AblationConfig()
    for name in names:
        if name == "rag":
            config.use_retrieval = True
        elif name == "parallel":
            config.parallel_scoring = True
        elif name == "topk-router":
            config.major_top_k = max(config.major_top_k, 2)
            config.middle_top_k = max(config.middle_top_k, 2)
        else:
            supported = ", ".join(sorted(SUPPORTED_ABLATIONS))
            raise ValueError(
                f"Unknown ablation {name!r}. Supported ablations: {supported}"
            )
    return config


def list_supported_ablations() -> List[str]:
    """Return supported ablation names in stable order."""

    return sorted(SUPPORTED_ABLATIONS)
