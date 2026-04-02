"""Two-line main workflows for EvoPrompt.

The repository's first-class workflows are:
1. Evolve prompts for each router/detector stage.
2. Evaluate vulnerability detection with the frozen prompt bundle.

Everything else should be treated as an ablation layered on top of this
baseline.
"""

from .ablations import AblationConfig, apply_ablation_presets
from .artifacts import PromptArtifact
from .system import MainlineDetectorSystem, MainlineDetectionResult
from .workflows import (
    EvaluationWorkflowConfig,
    EvolutionWorkflowConfig,
    run_evaluation_workflow,
    run_evolution_workflow,
)

__all__ = [
    "AblationConfig",
    "apply_ablation_presets",
    "PromptArtifact",
    "MainlineDetectorSystem",
    "MainlineDetectionResult",
    "EvaluationWorkflowConfig",
    "EvolutionWorkflowConfig",
    "run_evolution_workflow",
    "run_evaluation_workflow",
]
