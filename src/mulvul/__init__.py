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
    EvaluationWorkflowConfig,
    EvolutionWorkflowConfig,
    MainlineDetectorSystem,
    PromptArtifact,
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
    "EvolutionWorkflowConfig",
    "EvaluationWorkflowConfig",
    "PromptArtifact",
    "MainlineDetectorSystem",
    "run_evolution_workflow",
    "run_evaluation_workflow",
    "VulnerabilityDetectionWorkflow",
]
