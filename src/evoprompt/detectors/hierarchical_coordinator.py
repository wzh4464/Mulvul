"""Hierarchical detection coordinator with meta-learning integration.

Orchestrates the parallel hierarchical detector with error tracking
and automatic prompt tuning via meta-learning.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from ..llm.async_client import AsyncLLMClient
from ..meta.error_accumulator import ErrorAccumulator, ClassificationError
from ..meta.prompt_tuner import MetaLearningPromptTuner, TuningResult
from .parallel_hierarchical_detector import (
    ParallelHierarchicalDetector,
    ParallelDetectorConfig,
    HierarchicalPromptSet,
    CodeEnhancer,
)
from .scoring import DetectionPath, SelectionStrategy
from ..rag.retriever import CodeSimilarityRetriever


logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result of a single detection.
    
    Attributes:
        code: Original code analyzed
        paths: Detection paths from the detector
        final_prediction: Selected final prediction
        ground_truth: Ground truth label (if provided)
        is_correct: Whether prediction matched ground truth
        detection_time_ms: Time taken for detection
    """
    code: str
    paths: List[DetectionPath]
    final_prediction: Optional[str] = None
    ground_truth: Optional[str] = None
    is_correct: Optional[bool] = None
    detection_time_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "final_prediction": self.final_prediction,
            "ground_truth": self.ground_truth,
            "is_correct": self.is_correct,
            "num_paths": len(self.paths),
            "detection_time_ms": self.detection_time_ms,
            "top_path": self.paths[0].to_dict() if self.paths else None,
        }


@dataclass
class CoordinatorConfig:
    """Configuration for the detection coordinator.
    
    Attributes:
        enable_meta_learning: Whether to enable automatic prompt tuning
        meta_learning_check_interval: Check meta-learning every N samples
        save_checkpoints: Whether to save prompt checkpoints after tuning
        checkpoint_dir: Directory for checkpoints
        verbose: Enable verbose logging
    """
    enable_meta_learning: bool = True
    meta_learning_check_interval: int = 100
    save_checkpoints: bool = True
    checkpoint_dir: str = "outputs/checkpoints"
    verbose: bool = False


class HierarchicalDetectionCoordinator:
    """Coordinates hierarchical detection with meta-learning.
    
    Wraps the parallel hierarchical detector with:
    - Error tracking and accumulation
    - Automatic meta-learning triggers
    - Prompt optimization
    - Statistics collection
    """
    
    def __init__(
        self,
        llm_client: AsyncLLMClient,
        prompt_set: HierarchicalPromptSet,
        detector_config: Optional[ParallelDetectorConfig] = None,
        coordinator_config: Optional[CoordinatorConfig] = None,
        enhancer: Optional[CodeEnhancer] = None,
        selection_strategy: Optional[SelectionStrategy] = None,
        error_accumulator: Optional[ErrorAccumulator] = None,
        prompt_tuner: Optional[MetaLearningPromptTuner] = None,
        retriever: Optional[CodeSimilarityRetriever] = None,
    ):
        """Initialize the coordinator.

        Args:
            llm_client: Async LLM client
            prompt_set: Hierarchical prompt set
            detector_config: Detector configuration
            coordinator_config: Coordinator configuration
            enhancer: Optional code enhancer
            selection_strategy: Selection strategy for final prediction
            error_accumulator: Error accumulator (created if not provided)
            prompt_tuner: Prompt tuner (created if not provided)
            retriever: Optional RAG retriever for prompt enhancement
        """
        self.llm_client = llm_client
        self.prompt_set = prompt_set
        self.config = coordinator_config or CoordinatorConfig()
        self.detector_config = detector_config

        # Initialize detector
        self.detector = ParallelHierarchicalDetector(
            llm_client=llm_client,
            prompt_set=prompt_set,
            config=detector_config,
            enhancer=enhancer,
            selection_strategy=selection_strategy,
            retriever=retriever,
        )
        
        # Initialize meta-learning components
        self.error_accumulator = error_accumulator or ErrorAccumulator()
        self.prompt_tuner = prompt_tuner or MetaLearningPromptTuner(llm_client)
        
        # Tracking
        self._sample_count = 0
        self._results: List[DetectionResult] = []
        self._tuning_events: List[Tuple[datetime, List[TuningResult]]] = []
    
    async def detect_single_async(
        self,
        code: str,
        ground_truth: Optional[str] = None,
    ) -> DetectionResult:
        """Detect vulnerabilities in a single code sample.
        
        Args:
            code: Source code to analyze
            ground_truth: Optional ground truth label for tracking
            
        Returns:
            Detection result
        """
        import time
        start_time = time.time()
        
        # Run detection
        paths = await self.detector.detect_async(code)
        
        detection_time = (time.time() - start_time) * 1000  # ms
        
        # Get final prediction
        final_prediction = paths[0].get_final_prediction() if paths else None
        
        # Create result
        result = DetectionResult(
            code=code,
            paths=paths,
            final_prediction=final_prediction,
            ground_truth=ground_truth,
            detection_time_ms=detection_time,
        )
        
        # Record result (tracks errors if ground truth provided)
        self._record_result(result)
        
        # Check meta-learning trigger
        await self._maybe_trigger_meta_learning()
        
        return result
    
    def detect_single(
        self,
        code: str,
        ground_truth: Optional[str] = None,
    ) -> DetectionResult:
        """Synchronous wrapper for detect_single_async."""
        return asyncio.run(self.detect_single_async(code, ground_truth))
    
    async def detect_batch_async(
        self,
        codes: List[str],
        ground_truths: Optional[List[str]] = None,
        show_progress: bool = True,
    ) -> List[DetectionResult]:
        """Detect vulnerabilities in multiple code samples.
        
        Args:
            codes: List of code samples
            ground_truths: Optional list of ground truth labels
            show_progress: Whether to log progress
            
        Returns:
            List of detection results
        """
        if ground_truths is None:
            ground_truths = [None] * len(codes)
        
        if len(codes) != len(ground_truths):
            raise ValueError("codes and ground_truths must have same length")
        
        results = []
        for i, (code, gt) in enumerate(zip(codes, ground_truths)):
            result = await self.detect_single_async(code, gt)
            results.append(result)
            
            if show_progress and (i + 1) % 10 == 0:
                correct = sum(1 for r in results if r.is_correct)
                total_with_gt = sum(1 for r in results if r.ground_truth is not None)
                acc = correct / total_with_gt if total_with_gt > 0 else 0
                
                logger.info(
                    f"Progress: {i + 1}/{len(codes)} samples, "
                    f"accuracy: {acc:.2%}"
                )
        
        return results
    
    def detect_batch(
        self,
        codes: List[str],
        ground_truths: Optional[List[str]] = None,
        show_progress: bool = True,
    ) -> List[DetectionResult]:
        """Synchronous wrapper for detect_batch_async."""
        return asyncio.run(
            self.detect_batch_async(codes, ground_truths, show_progress)
        )
    
    def _record_result(self, result: DetectionResult) -> None:
        """Record a detection result and track errors.
        
        Args:
            result: Detection result to record
        """
        self._sample_count += 1
        self._results.append(result)
        
        # Limit stored results to prevent memory issues
        if len(self._results) > 10000:
            self._results = self._results[-5000:]
        
        # Check correctness and track errors
        if result.ground_truth is not None:
            predicted = result.final_prediction or "unknown"
            actual = result.ground_truth
            
            # Normalize for comparison
            pred_lower = predicted.lower()
            actual_lower = actual.lower()
            
            # Check if correct (handle various formats)
            is_correct = self._check_prediction_match(pred_lower, actual_lower)
            result.is_correct = is_correct
            
            if is_correct:
                self.error_accumulator.add_correct_prediction()
            else:
                # Determine which layer made the error
                layer = self._identify_error_layer(result.paths, actual)
                
                error = ClassificationError.from_detection_result(
                    code=result.code,
                    predicted=predicted,
                    actual=actual,
                    layer=layer,
                    confidence=result.paths[0].aggregated_confidence if result.paths else 0.0,
                    predicted_cwe=result.paths[0].layer3_cwe if result.paths else None,
                    actual_cwe=actual if actual.upper().startswith("CWE-") else None,
                )
                self.error_accumulator.add_error(error)
                
                if self.config.verbose:
                    logger.debug(
                        f"Error: predicted '{predicted}', actual '{actual}'"
                    )
    
    def _check_prediction_match(self, predicted: str, actual: str) -> bool:
        """Check if prediction matches ground truth.
        
        Handles various label formats (CWE, category names, etc.)
        
        Args:
            predicted: Predicted label (lowercase)
            actual: Actual label (lowercase)
            
        Returns:
            True if prediction is considered correct
        """
        # Exact match
        if predicted == actual:
            return True
        
        # CWE match (both are CWE IDs)
        if predicted.startswith("cwe-") and actual.startswith("cwe-"):
            return predicted == actual
        
        # Benign/non-vulnerable match
        benign_terms = {"benign", "safe", "non-vulnerable", "0", "safe_code"}
        if predicted in benign_terms and actual in benign_terms:
            return True
        
        # Category containment (e.g., "memory" in "Memory")
        if predicted in actual or actual in predicted:
            return True
        
        return False
    
    def _identify_error_layer(
        self, 
        paths: List[DetectionPath], 
        ground_truth: str
    ) -> int:
        """Identify which layer made the error.
        
        Args:
            paths: Detection paths
            ground_truth: Ground truth label
            
        Returns:
            Layer number (1, 2, or 3)
        """
        if not paths:
            return 1
        
        top_path = paths[0]
        gt_lower = ground_truth.lower()
        
        # Check if Layer 1 category is wrong
        if gt_lower.startswith("cwe-"):
            # Ground truth is CWE, so error is at layer 3 if we have layer 3
            if top_path.layer3_cwe:
                return 3
            return 2
        
        # Check major category match
        if top_path.layer1_category.lower() not in gt_lower:
            if gt_lower not in top_path.layer1_category.lower():
                return 1
        
        # Check middle category
        if top_path.layer2_category:
            if top_path.layer2_category.lower() not in gt_lower:
                if gt_lower not in top_path.layer2_category.lower():
                    return 2
        
        return 3
    
    async def _maybe_trigger_meta_learning(self) -> None:
        """Check if meta-learning should be triggered and run if so."""
        if not self.config.enable_meta_learning:
            return
        
        # Only check periodically
        if self._sample_count % self.config.meta_learning_check_interval != 0:
            return
        
        # Check if threshold met
        if not self.error_accumulator.should_trigger_meta_learning():
            return
        
        logger.info("Triggering meta-learning prompt optimization...")
        
        # Run prompt tuning
        results = await self.prompt_tuner.tune_prompts_async(
            prompt_set=self.prompt_set,
            error_accumulator=self.error_accumulator,
        )
        
        self._tuning_events.append((datetime.now(), results))
        
        # Save checkpoint if enabled
        if self.config.save_checkpoints and results:
            self._save_checkpoint()
    
    def _save_checkpoint(self) -> None:
        """Save prompt checkpoint after tuning."""
        import os
        import json
        
        os.makedirs(self.config.checkpoint_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"prompts_checkpoint_{timestamp}.json"
        filepath = os.path.join(self.config.checkpoint_dir, filename)
        
        checkpoint = {
            "timestamp": timestamp,
            "sample_count": self._sample_count,
            "layer1_prompts": self.prompt_set.layer1_prompts,
            "layer2_prompts": self.prompt_set.layer2_prompts,
            "layer3_prompts": self.prompt_set.layer3_prompts,
            "tuning_count": len(self._tuning_events),
        }
        
        with open(filepath, "w") as f:
            json.dump(checkpoint, f, indent=2)
        
        logger.info(f"Saved checkpoint: {filepath}")
    
    def get_statistics_summary(self) -> Dict[str, Any]:
        """Get comprehensive statistics summary.
        
        Returns:
            Summary dictionary with detection and meta-learning stats
        """
        # Detection statistics
        total = len(self._results)
        with_gt = [r for r in self._results if r.ground_truth is not None]
        correct = sum(1 for r in with_gt if r.is_correct)
        
        # Timing statistics
        times = [r.detection_time_ms for r in self._results if r.detection_time_ms > 0]
        avg_time = sum(times) / len(times) if times else 0
        
        summary = {
            "detection": {
                "total_samples": total,
                "samples_with_ground_truth": len(with_gt),
                "correct_predictions": correct,
                "accuracy": f"{correct / len(with_gt):.2%}" if with_gt else "N/A",
                "avg_detection_time_ms": f"{avg_time:.1f}",
            },
            "error_tracking": self.error_accumulator.get_summary(),
            "meta_learning": {
                "enabled": self.config.enable_meta_learning,
                "tuning_events": len(self._tuning_events),
                "tuner_summary": self.prompt_tuner.get_summary(),
            },
        }

        # Add RAG stats if enabled
        det_config = self.detector_config or ParallelDetectorConfig()
        if det_config.enable_rag:
            summary["rag"] = {
                "enabled": True,
                "top_k": det_config.rag_top_k,
                "retriever_type": det_config.rag_retriever_type,
            }

        return summary
    
    def get_recent_errors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent classification errors.
        
        Args:
            limit: Maximum errors to return
            
        Returns:
            List of error dictionaries
        """
        errors = []
        for r in reversed(self._results):
            if r.is_correct is False:
                errors.append({
                    "predicted": r.final_prediction,
                    "actual": r.ground_truth,
                    "code_preview": r.code[:100] + "..." if len(r.code) > 100 else r.code,
                })
                if len(errors) >= limit:
                    break
        return errors
    
    def reset_statistics(self) -> None:
        """Reset all statistics and error tracking."""
        self._sample_count = 0
        self._results.clear()
        self._tuning_events.clear()
        self.error_accumulator.reset()
        logger.info("Coordinator statistics reset")


def create_coordinator(
    llm_client: AsyncLLMClient,
    enable_meta_learning: bool = True,
    knowledge_base=None,
    prompt_change_logger=None,
    **kwargs
) -> HierarchicalDetectionCoordinator:
    """Factory function to create a detection coordinator.

    Args:
        llm_client: Async LLM client
        enable_meta_learning: Whether to enable meta-learning
        knowledge_base: Optional KnowledgeBase for RAG enhancement
        prompt_change_logger: Optional PromptChangeLogger for always-on change tracking
        **kwargs: Additional configuration (including enable_rag, rag_top_k, rag_retriever_type)

    Returns:
        Configured HierarchicalDetectionCoordinator
    """
    from ..prompts.hierarchical_three_layer import ThreeLayerPromptFactory

    # Create default prompt set
    base_prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()
    hierarchical_prompts = HierarchicalPromptSet.from_three_layer_set(base_prompt_set)

    # Create configurations
    detector_config = ParallelDetectorConfig(
        layer1_top_k=kwargs.get("layer1_top_k", 2),
        layer2_top_k=kwargs.get("layer2_top_k", 2),
        layer3_top_k=kwargs.get("layer3_top_k", 1),
        enable_rag=kwargs.get("enable_rag", False),
        rag_top_k=kwargs.get("rag_top_k", 2),
        rag_retriever_type=kwargs.get("rag_retriever_type", "lexical"),
    )

    coordinator_config = CoordinatorConfig(
        enable_meta_learning=enable_meta_learning,
        meta_learning_check_interval=kwargs.get("meta_learning_check_interval", 100),
        save_checkpoints=kwargs.get("save_checkpoints", True),
        verbose=kwargs.get("verbose", False),
    )

    # Create retriever if RAG is enabled and KB is provided
    retriever = None
    if detector_config.enable_rag and knowledge_base is not None:
        from ..rag.retriever import create_retriever
        retriever = create_retriever(
            knowledge_base,
            retriever_type=detector_config.rag_retriever_type,
        )

    # Create prompt tuner with change logger
    prompt_tuner = MetaLearningPromptTuner(
        llm_client,
        prompt_change_logger=prompt_change_logger,
    )

    return HierarchicalDetectionCoordinator(
        llm_client=llm_client,
        prompt_set=hierarchical_prompts,
        detector_config=detector_config,
        coordinator_config=coordinator_config,
        retriever=retriever,
        prompt_tuner=prompt_tuner,
    )
