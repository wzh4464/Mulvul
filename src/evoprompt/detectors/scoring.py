"""Scoring and selection interfaces for hierarchical detection.

Provides data structures for scored predictions and selection strategies
for combining results across detection layers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum


@dataclass
class ScoredPrediction:
    """A single prediction with confidence score.
    
    Attributes:
        category: Category name (MajorCategory value, MiddleCategory value, or CWE ID)
        confidence: Confidence score between 0.0 and 1.0
        layer: Detection layer (1, 2, or 3)
        parent_category: Parent category from previous layer
        raw_response: Original LLM response (for debugging)
    """
    category: str
    confidence: float
    layer: int
    parent_category: Optional[str] = None
    raw_response: Optional[str] = None
    
    def __post_init__(self):
        """Validate confidence is in valid range."""
        self.confidence = max(0.0, min(1.0, self.confidence))


@dataclass
class DetectionPath:
    """Complete detection path through all layers.
    
    Represents the full classification path: Layer1 → Layer2 → Layer3
    with aggregated confidence score.
    
    Attributes:
        layer1_category: Major category from Layer 1
        layer1_confidence: Confidence from Layer 1
        layer2_category: Middle category from Layer 2
        layer2_confidence: Confidence from Layer 2
        layer3_cwe: CWE ID from Layer 3
        layer3_confidence: Confidence from Layer 3
        aggregated_confidence: Combined confidence score
        metadata: Additional metadata for debugging
    """
    layer1_category: str
    layer1_confidence: float
    layer2_category: Optional[str] = None
    layer2_confidence: Optional[float] = None
    layer3_cwe: Optional[str] = None
    layer3_confidence: Optional[float] = None
    aggregated_confidence: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def compute_aggregated_confidence(
        self, 
        weights: Optional[Dict[str, float]] = None
    ) -> float:
        """Compute weighted aggregated confidence.
        
        Args:
            weights: Dict with keys 'layer1', 'layer2', 'layer3' mapping to weights.
                    Defaults to equal weights.
        
        Returns:
            Aggregated confidence score.
        """
        if weights is None:
            weights = {"layer1": 1.0, "layer2": 1.0, "layer3": 1.0}
        
        total_weight = 0.0
        weighted_sum = 0.0
        
        if self.layer1_confidence is not None:
            weighted_sum += weights.get("layer1", 1.0) * self.layer1_confidence
            total_weight += weights.get("layer1", 1.0)
        
        if self.layer2_confidence is not None:
            weighted_sum += weights.get("layer2", 1.0) * self.layer2_confidence
            total_weight += weights.get("layer2", 1.0)
        
        if self.layer3_confidence is not None:
            weighted_sum += weights.get("layer3", 1.0) * self.layer3_confidence
            total_weight += weights.get("layer3", 1.0)
        
        self.aggregated_confidence = weighted_sum / total_weight if total_weight > 0 else 0.0
        return self.aggregated_confidence
    
    def get_final_prediction(self) -> str:
        """Get the most specific prediction available.
        
        Returns CWE if available, else middle category, else major category.
        """
        if self.layer3_cwe:
            return self.layer3_cwe
        if self.layer2_category:
            return self.layer2_category
        return self.layer1_category
    
    def is_benign(self) -> bool:
        """Check if this path indicates benign (non-vulnerable) code."""
        return self.layer1_category.lower() == "benign"
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "layer1": {
                "category": self.layer1_category,
                "confidence": self.layer1_confidence,
            },
            "layer2": {
                "category": self.layer2_category,
                "confidence": self.layer2_confidence,
            } if self.layer2_category else None,
            "layer3": {
                "cwe": self.layer3_cwe,
                "confidence": self.layer3_confidence,
            } if self.layer3_cwe else None,
            "aggregated_confidence": self.aggregated_confidence,
            "final_prediction": self.get_final_prediction(),
            "metadata": self.metadata,
        }


class SelectionStrategy(ABC):
    """Abstract base class for prediction selection strategies.
    
    Selection strategies determine how to combine and rank detection paths
    from hierarchical detection.
    """
    
    @abstractmethod
    def select(
        self, 
        paths: List[DetectionPath], 
        top_k: int = 1
    ) -> List[DetectionPath]:
        """Select top-k paths based on the strategy.
        
        Args:
            paths: List of detection paths to select from
            top_k: Number of paths to return
            
        Returns:
            List of selected paths, ordered by preference (best first)
        """
        pass
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return strategy name for logging."""
        pass


class MaxConfidenceSelection(SelectionStrategy):
    """Simple selection based on maximum aggregated confidence.
    
    Selects paths with highest aggregated confidence scores.
    """
    
    def __init__(self, weights: Optional[Dict[str, float]] = None):
        """Initialize with optional layer weights.
        
        Args:
            weights: Dict with keys 'layer1', 'layer2', 'layer3' mapping to weights.
        """
        self.weights = weights
    
    def select(
        self, 
        paths: List[DetectionPath], 
        top_k: int = 1
    ) -> List[DetectionPath]:
        """Select top-k paths by maximum confidence.
        
        Args:
            paths: Detection paths to select from
            top_k: Number of paths to return
            
        Returns:
            Top-k paths sorted by aggregated confidence (descending)
        """
        if not paths:
            return []
        
        # Compute aggregated confidence for all paths
        for path in paths:
            path.compute_aggregated_confidence(self.weights)
        
        # Sort by aggregated confidence (descending)
        sorted_paths = sorted(
            paths, 
            key=lambda p: p.aggregated_confidence or 0.0, 
            reverse=True
        )
        
        return sorted_paths[:top_k]
    
    @property
    def name(self) -> str:
        return "MaxConfidenceSelection"


class ThresholdSelection(SelectionStrategy):
    """Selection based on confidence threshold filtering.
    
    Only includes paths that meet minimum confidence thresholds,
    then selects top-k by confidence.
    """
    
    def __init__(
        self, 
        min_layer1: float = 0.3,
        min_layer2: float = 0.3,
        min_layer3: float = 0.3,
        min_aggregated: float = 0.0,
        weights: Optional[Dict[str, float]] = None
    ):
        """Initialize threshold selection.
        
        Args:
            min_layer1: Minimum Layer 1 confidence
            min_layer2: Minimum Layer 2 confidence
            min_layer3: Minimum Layer 3 confidence
            min_aggregated: Minimum aggregated confidence
            weights: Layer weights for aggregation
        """
        self.min_layer1 = min_layer1
        self.min_layer2 = min_layer2
        self.min_layer3 = min_layer3
        self.min_aggregated = min_aggregated
        self.weights = weights
    
    def select(
        self, 
        paths: List[DetectionPath], 
        top_k: int = 1
    ) -> List[DetectionPath]:
        """Select paths meeting threshold requirements.
        
        Args:
            paths: Detection paths to filter and select
            top_k: Maximum paths to return
            
        Returns:
            Filtered paths sorted by aggregated confidence
        """
        if not paths:
            return []
        
        filtered = []
        for path in paths:
            # Check layer thresholds
            if path.layer1_confidence < self.min_layer1:
                continue
            if path.layer2_confidence is not None and path.layer2_confidence < self.min_layer2:
                continue
            if path.layer3_confidence is not None and path.layer3_confidence < self.min_layer3:
                continue
            
            # Compute aggregated confidence
            path.compute_aggregated_confidence(self.weights)
            
            if (path.aggregated_confidence or 0.0) >= self.min_aggregated:
                filtered.append(path)
        
        # Sort by aggregated confidence
        sorted_paths = sorted(
            filtered,
            key=lambda p: p.aggregated_confidence or 0.0,
            reverse=True
        )
        
        return sorted_paths[:top_k]
    
    @property
    def name(self) -> str:
        return "ThresholdSelection"


# TODO: WeightedVotingSelection - 加权投票
# TODO: EnsembleSelection - 多策略组合
# TODO: Layer-specific weights - 层级权重调整


def create_selection_strategy(
    strategy_name: str,
    **kwargs
) -> SelectionStrategy:
    """Factory function to create selection strategies.
    
    Args:
        strategy_name: Name of strategy ('max_confidence', 'threshold')
        **kwargs: Strategy-specific parameters
        
    Returns:
        Configured selection strategy instance
    """
    strategies = {
        "max_confidence": MaxConfidenceSelection,
        "threshold": ThresholdSelection,
    }
    
    if strategy_name not in strategies:
        raise ValueError(f"Unknown strategy: {strategy_name}. Available: {list(strategies.keys())}")
    
    return strategies[strategy_name](**kwargs)
