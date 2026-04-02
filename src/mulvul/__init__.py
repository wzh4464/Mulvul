"""Mulvul: Mainline prompt evolution for vulnerability detection."""

__version__ = "0.1.0"
__author__ = "Mulvul Team"

from .core.evolution import EvolutionEngine
from .core.evaluator import Evaluator  
from .algorithms.genetic import GeneticAlgorithm
from .algorithms.differential import DifferentialEvolution
from .llm.client import SVENLLMClient, sven_llm_init, sven_llm_query
from .mainline import (
    AblationConfig,
    BundleDefaults,
    EvaluationWorkflowConfig,
    EvaluationResult,
    EvaluationSample,
    EvolutionWorkflowConfig,
    GreedyCascadePolicy,
    LLMNodeScorer,
    MainlineDetectorSystem,
    MainlineEvaluator,
    NodeMetrics,
    NodeScoreResult,
    NodeSpec,
    PromptArtifact,
    PromptBundle,
    PromptBundleAdapter,
    PromptBundleIO,
    ScorerContext,
    TaxonomyGraph,
    TaxonomyNode,
    TopKCascadePolicy,
    run_evaluation_workflow,
    run_evolution_workflow,
)
from .workflows.vulnerability_detection import VulnerabilityDetectionWorkflow

__all__ = [
    "EvolutionEngine",
    "Evaluator", 
    "GeneticAlgorithm",
    "DifferentialEvolution",
    "SVENLLMClient",
    "sven_llm_init", 
    "sven_llm_query",
    "AblationConfig",
    "TaxonomyNode",
    "TaxonomyGraph",
    "NodeSpec",
    "BundleDefaults",
    "PromptBundle",
    "PromptBundleAdapter",
    "PromptBundleIO",
    "ScorerContext",
    "NodeScoreResult",
    "LLMNodeScorer",
    "GreedyCascadePolicy",
    "TopKCascadePolicy",
    "EvaluationSample",
    "EvaluationResult",
    "NodeMetrics",
    "MainlineEvaluator",
    "EvolutionWorkflowConfig",
    "EvaluationWorkflowConfig",
    "PromptArtifact",
    "MainlineDetectorSystem",
    "run_evolution_workflow",
    "run_evaluation_workflow",
    "VulnerabilityDetectionWorkflow",
]
