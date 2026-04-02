"""MulVul Multi-Agent Detection System

Implements the Router-Detector architecture from method.md:
- RouterAgent: Top-k category routing with cross-type contrastive retrieval
- DetectorAgent: Category-specific vulnerability detection
- DecisionAggregator: Confidence-based decision aggregation
- MulVulDetector: Complete detection pipeline
"""

from .base import DetectionResult
from .router_agent import RouterAgent
from .detector_agent import DetectorAgent, DetectorAgentFactory
from .aggregator import DecisionAggregator
from .mulvul import MulVulDetector

__all__ = [
    "DetectionResult",
    "RouterAgent",
    "DetectorAgent",
    "DetectorAgentFactory",
    "DecisionAggregator",
    "MulVulDetector",
]
