"""Two-line main workflows for Mulvul.

The repository's first-class workflows are:
1. Evolve prompts for each router/detector stage.
2. Evaluate vulnerability detection with the frozen prompt bundle.

Everything else should be treated as an ablation layered on top of this
baseline.
"""

from .ablations import AblationConfig, apply_ablation_presets
from .artifacts import PromptArtifact
from .bundle import (
    BundleDefaults,
    EvidenceBundle,
    EvidenceItem,
    NodeScoreResult,
    NodeSpec,
    PromptBundle,
    PromptBundleAdapter,
    PromptBundleIO,
    ScorerContext,
    TaxonomyGraph,
    TaxonomyNode,
)
from .evaluator import EvaluationResult, EvaluationSample, MainlineEvaluator, NodeMetrics
from .policy import DetectionPath, GreedyCascadePolicy, InferenceResult, TopKCascadePolicy
from .scorer import LLMNodeScorer, NodeScorer
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
    "TaxonomyNode",
    "TaxonomyGraph",
    "NodeSpec",
    "EvidenceItem",
    "EvidenceBundle",
    "BundleDefaults",
    "PromptBundle",
    "ScorerContext",
    "NodeScoreResult",
    "PromptBundleAdapter",
    "PromptBundleIO",
    "NodeScorer",
    "LLMNodeScorer",
    "DetectionPath",
    "InferenceResult",
    "GreedyCascadePolicy",
    "TopKCascadePolicy",
    "EvaluationSample",
    "EvaluationResult",
    "NodeMetrics",
    "MainlineEvaluator",
    "MainlineDetectorSystem",
    "MainlineDetectionResult",
    "EvaluationWorkflowConfig",
    "EvolutionWorkflowConfig",
    "run_evolution_workflow",
    "run_evaluation_workflow",
]
