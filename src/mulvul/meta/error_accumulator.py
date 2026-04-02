"""Error accumulation for meta-learning prompt optimization.

Tracks classification errors and identifies patterns to guide
prompt improvement via meta-learning.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum


logger = logging.getLogger(__name__)


class ErrorType(Enum):
    """Types of classification errors."""
    FALSE_POSITIVE = "false_positive"  # Predicted vulnerable, actually benign
    FALSE_NEGATIVE = "false_negative"  # Predicted benign, actually vulnerable
    CATEGORY_MISMATCH = "category_mismatch"  # Wrong vulnerability category
    CWE_MISMATCH = "cwe_mismatch"  # Wrong specific CWE


@dataclass
class ClassificationError:
    """Record of a single classification error.
    
    Attributes:
        code_snippet: The code that was misclassified (truncated)
        predicted_category: What the detector predicted
        actual_category: Ground truth category
        predicted_cwe: Predicted CWE (if applicable)
        actual_cwe: Actual CWE (if applicable)
        layer: Which layer made the error (1, 2, or 3)
        confidence: Detector's confidence in the wrong prediction
        error_type: Type of error (FP, FN, category mismatch, etc.)
        timestamp: When the error occurred
        metadata: Additional context
    """
    code_snippet: str
    predicted_category: str
    actual_category: str
    predicted_cwe: Optional[str] = None
    actual_cwe: Optional[str] = None
    layer: int = 1
    confidence: float = 0.0
    error_type: ErrorType = ErrorType.CATEGORY_MISMATCH
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_detection_result(
        cls,
        code: str,
        predicted: str,
        actual: str,
        layer: int = 1,
        confidence: float = 0.0,
        predicted_cwe: Optional[str] = None,
        actual_cwe: Optional[str] = None,
        max_snippet_length: int = 500,
    ) -> "ClassificationError":
        """Create error from detection result.
        
        Args:
            code: Full source code
            predicted: Predicted category
            actual: Actual category
            layer: Detection layer
            confidence: Prediction confidence
            predicted_cwe: Predicted CWE ID
            actual_cwe: Actual CWE ID
            max_snippet_length: Max length for code snippet
        """
        # Determine error type
        pred_lower = predicted.lower()
        actual_lower = actual.lower()
        
        if actual_lower == "benign" and pred_lower != "benign":
            error_type = ErrorType.FALSE_POSITIVE
        elif pred_lower == "benign" and actual_lower != "benign":
            error_type = ErrorType.FALSE_NEGATIVE
        elif predicted_cwe and actual_cwe and predicted_cwe != actual_cwe:
            error_type = ErrorType.CWE_MISMATCH
        else:
            error_type = ErrorType.CATEGORY_MISMATCH
        
        # Truncate code snippet
        snippet = code[:max_snippet_length]
        if len(code) > max_snippet_length:
            snippet += "..."
        
        return cls(
            code_snippet=snippet,
            predicted_category=predicted,
            actual_category=actual,
            predicted_cwe=predicted_cwe,
            actual_cwe=actual_cwe,
            layer=layer,
            confidence=confidence,
            error_type=error_type,
        )


@dataclass
class ErrorPattern:
    """Aggregated pattern of confusion between categories.
    
    Represents a frequently occurring misclassification pattern.
    
    Attributes:
        predicted_category: Category that is incorrectly predicted
        actual_category: Category that should have been predicted
        count: Number of times this confusion occurred
        avg_confidence: Average confidence of the wrong predictions
        example_snippets: Representative code snippets
        layer: Detection layer where confusion occurs
    """
    predicted_category: str
    actual_category: str
    count: int = 0
    avg_confidence: float = 0.0
    example_snippets: List[str] = field(default_factory=list)
    layer: int = 1
    
    @property
    def confusion_key(self) -> Tuple[str, str]:
        """Get confusion pair key."""
        return (self.predicted_category, self.actual_category)
    
    def add_error(self, error: ClassificationError) -> None:
        """Add an error to this pattern.
        
        Args:
            error: Classification error to add
        """
        # Update running average of confidence
        total_conf = self.avg_confidence * self.count + error.confidence
        self.count += 1
        self.avg_confidence = total_conf / self.count
        
        # Keep up to 5 example snippets
        if len(self.example_snippets) < 5:
            self.example_snippets.append(error.code_snippet)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "predicted": self.predicted_category,
            "actual": self.actual_category,
            "count": self.count,
            "avg_confidence": self.avg_confidence,
            "layer": self.layer,
            "examples": self.example_snippets,
        }


class ErrorAccumulator:
    """Accumulates and analyzes classification errors.
    
    Tracks errors over time and identifies patterns to guide
    meta-learning prompt optimization.
    """
    
    def __init__(
        self,
        threshold_count: int = 50,
        threshold_rate: float = 0.15,
        window_size: int = 200,
        max_stored_errors: int = 1000,
    ):
        """Initialize error accumulator.
        
        Args:
            threshold_count: Minimum errors to trigger meta-learning
            threshold_rate: Error rate threshold for meta-learning
            window_size: Window size for rate calculation
            max_stored_errors: Maximum errors to store in memory
        """
        self.threshold_count = threshold_count
        self.threshold_rate = threshold_rate
        self.window_size = window_size
        self.max_stored_errors = max_stored_errors
        
        # Error storage
        self._errors: List[ClassificationError] = []
        
        # Pattern tracking by layer
        self._patterns_by_layer: Dict[int, Dict[Tuple[str, str], ErrorPattern]] = {
            1: {},
            2: {},
            3: {},
        }
        
        # Counters
        self._total_predictions = 0
        self._recent_predictions: List[bool] = []  # True = correct
        
        # Meta-learning tracking
        self._last_meta_learning_trigger: Optional[datetime] = None
        self._meta_learning_count = 0
    
    def add_error(self, error: ClassificationError) -> None:
        """Add a classification error.
        
        Args:
            error: Classification error to add
        """
        # Store error (with limit)
        self._errors.append(error)
        if len(self._errors) > self.max_stored_errors:
            self._errors = self._errors[-self.max_stored_errors:]
        
        # Update pattern
        key = (error.predicted_category, error.actual_category)
        layer = error.layer
        
        if key not in self._patterns_by_layer[layer]:
            self._patterns_by_layer[layer][key] = ErrorPattern(
                predicted_category=error.predicted_category,
                actual_category=error.actual_category,
                layer=layer,
            )
        
        self._patterns_by_layer[layer][key].add_error(error)
        
        # Update counters
        self._total_predictions += 1
        self._recent_predictions.append(False)
        self._trim_recent_predictions()
        
        logger.debug(
            f"Error recorded: {error.predicted_category} → {error.actual_category} "
            f"(Layer {layer}, confidence: {error.confidence:.2f})"
        )
    
    def add_correct_prediction(self) -> None:
        """Record a correct prediction."""
        self._total_predictions += 1
        self._recent_predictions.append(True)
        self._trim_recent_predictions()
    
    def add_batch_errors(self, errors: List[ClassificationError]) -> None:
        """Add multiple errors at once.
        
        Args:
            errors: List of classification errors
        """
        for error in errors:
            self.add_error(error)
    
    def _trim_recent_predictions(self) -> None:
        """Keep only window_size recent predictions."""
        if len(self._recent_predictions) > self.window_size:
            self._recent_predictions = self._recent_predictions[-self.window_size:]
    
    @property
    def total_errors(self) -> int:
        """Get total error count."""
        return len(self._errors)
    
    @property
    def recent_error_rate(self) -> float:
        """Calculate error rate over recent window."""
        if not self._recent_predictions:
            return 0.0
        errors = sum(1 for p in self._recent_predictions if not p)
        return errors / len(self._recent_predictions)
    
    def should_trigger_meta_learning(self) -> bool:
        """Check if meta-learning should be triggered.
        
        Returns:
            True if error threshold is met and patterns exist
        """
        # Check minimum error count
        if self.total_errors < self.threshold_count:
            return False
        
        # Check error rate
        if self.recent_error_rate < self.threshold_rate:
            return False
        
        # Check if we have patterns to address
        total_patterns = sum(
            len(patterns) for patterns in self._patterns_by_layer.values()
        )
        if total_patterns == 0:
            return False
        
        logger.info(
            f"Meta-learning trigger check: errors={self.total_errors}, "
            f"rate={self.recent_error_rate:.2%}, patterns={total_patterns}"
        )
        
        return True
    
    def get_top_confusion_patterns(
        self, 
        top_k: int = 5,
        layer: Optional[int] = None,
        min_count: int = 3,
    ) -> List[ErrorPattern]:
        """Get top confusion patterns by frequency.
        
        Args:
            top_k: Number of patterns to return
            layer: Specific layer to query (None for all)
            min_count: Minimum occurrences to include
            
        Returns:
            List of top error patterns
        """
        patterns = []
        
        if layer is not None:
            layers = [layer]
        else:
            layers = [1, 2, 3]
        
        for l in layers:
            for pattern in self._patterns_by_layer[l].values():
                if pattern.count >= min_count:
                    patterns.append(pattern)
        
        # Sort by count (descending)
        patterns.sort(key=lambda p: p.count, reverse=True)
        
        return patterns[:top_k]
    
    def generate_meta_learning_context(self) -> Dict[str, Any]:
        """Generate context for meta-learning prompt tuning.
        
        Returns:
            Context dictionary for meta-learning
        """
        # Get top patterns for each layer
        layer_contexts = {}
        
        for layer in [1, 2, 3]:
            patterns = self.get_top_confusion_patterns(top_k=5, layer=layer)
            if patterns:
                layer_contexts[f"layer{layer}"] = {
                    "patterns": [p.to_dict() for p in patterns],
                    "total_errors": sum(p.count for p in patterns),
                }
        
        # Error type breakdown
        error_types = defaultdict(int)
        for error in self._errors:
            error_types[error.error_type.value] += 1
        
        # Recent performance
        context = {
            "total_predictions": self._total_predictions,
            "total_errors": self.total_errors,
            "recent_error_rate": self.recent_error_rate,
            "error_type_breakdown": dict(error_types),
            "layer_analysis": layer_contexts,
            "meta_learning_triggers": self._meta_learning_count,
            "timestamp": datetime.now().isoformat(),
        }
        
        return context
    
    def mark_meta_learning_triggered(self) -> None:
        """Record that meta-learning was triggered."""
        self._last_meta_learning_trigger = datetime.now()
        self._meta_learning_count += 1
        
        # Clear some error history after meta-learning
        # Keep recent errors for continued monitoring
        keep_count = self.max_stored_errors // 2
        if len(self._errors) > keep_count:
            self._errors = self._errors[-keep_count:]
        
        logger.info(f"Meta-learning triggered (count: {self._meta_learning_count})")
    
    def get_errors_for_category(
        self, 
        category: str,
        layer: Optional[int] = None,
        limit: int = 50,
    ) -> List[ClassificationError]:
        """Get errors involving a specific category.
        
        Args:
            category: Category to filter by (predicted or actual)
            layer: Optional layer filter
            limit: Maximum errors to return
            
        Returns:
            List of matching errors
        """
        matches = []
        for error in reversed(self._errors):  # Most recent first
            if layer is not None and error.layer != layer:
                continue
            if error.predicted_category == category or error.actual_category == category:
                matches.append(error)
                if len(matches) >= limit:
                    break
        
        return matches
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics.
        
        Returns:
            Summary dictionary
        """
        return {
            "total_predictions": self._total_predictions,
            "total_errors": self.total_errors,
            "recent_error_rate": f"{self.recent_error_rate:.2%}",
            "patterns_by_layer": {
                layer: len(patterns) 
                for layer, patterns in self._patterns_by_layer.items()
            },
            "top_confusion": [
                f"{p.predicted_category}→{p.actual_category}: {p.count}"
                for p in self.get_top_confusion_patterns(top_k=3)
            ],
            "meta_learning_triggers": self._meta_learning_count,
            "should_trigger": self.should_trigger_meta_learning(),
        }
    
    def reset(self) -> None:
        """Reset all error tracking."""
        self._errors.clear()
        self._patterns_by_layer = {1: {}, 2: {}, 3: {}}
        self._total_predictions = 0
        self._recent_predictions.clear()
        logger.info("Error accumulator reset")
