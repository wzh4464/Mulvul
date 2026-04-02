"""CWE Category Evaluator for multi-class classification.

Instead of binary classification (vulnerable/benign), this evaluator
classifies code into CWE major categories:
- Memory (CWE-120, CWE-787, etc.)
- Injection (CWE-79, CWE-89, etc.)
- Logic
- Input
- Crypto
"""

from typing import List, Optional, Dict
import logging

from ..data.dataset import Dataset
from ..llm.client import LLMClient
from ..prompts.hierarchical import CWECategory, get_cwe_major_category
from .statistics import DetectionStatistics

logger = logging.getLogger(__name__)


class CWECategoryEvaluator:
    """Evaluator for CWE category classification (multi-class)."""

    def __init__(
        self,
        dataset: Dataset,
        llm_client: LLMClient,
        category_mapping: Optional[Dict[str, CWECategory]] = None
    ):
        """Initialize CWE category evaluator.

        Args:
            dataset: Dataset with CWE labels
            llm_client: LLM client for detection
            category_mapping: Optional custom CWE to category mapping
        """
        self.dataset = dataset
        self.llm_client = llm_client
        self.category_mapping = category_mapping or {}

    def evaluate(
        self,
        prompt: str,
        sample_size: Optional[int] = None
    ) -> DetectionStatistics:
        """Evaluate a prompt on category classification.

        Args:
            prompt: Prompt for category classification
                    Should ask for category name, not vulnerable/benign
            sample_size: Optional number of samples

        Returns:
            Statistics for category classification
        """
        samples = self.dataset.get_samples(sample_size)
        stats = DetectionStatistics()

        # Prepare prompts
        code_samples = [s.input_text for s in samples]
        formatted_prompts = [
            prompt.replace("{input}", code)
            for code in code_samples
        ]

        # Get predictions
        try:
            predictions = self.llm_client.batch_generate(
                formatted_prompts,
                temperature=0.1,
                batch_size=16
            )
        except Exception as e:
            logger.error(f"Batch generation failed: {e}")
            # Fallback to sequential
            predictions = []
            for p in formatted_prompts:
                try:
                    pred = self.llm_client.generate(p, temperature=0.1)
                    predictions.append(pred)
                except Exception as e2:
                    logger.error(f"Single generation failed: {e2}")
                    predictions.append("Unknown")

        # Collect statistics
        for sample, prediction in zip(samples, predictions):
            # Get actual category from CWE
            actual_category = self._get_sample_category(sample)

            # Normalize prediction
            pred_category = self._normalize_category(prediction)

            # Convert to strings for statistics
            actual_str = actual_category.value if actual_category else "Unknown"
            pred_str = pred_category.value if pred_category else "Unknown"

            # Add to statistics (treating as multi-class classification)
            stats.add_prediction(
                predicted=pred_str,
                actual=actual_str,
                category=actual_str,
                sample_id=getattr(sample, 'id', None)
            )

        stats.compute_metrics()
        return stats

    def _get_sample_category(self, sample) -> Optional[CWECategory]:
        """Get the actual CWE category for a sample.

        Args:
            sample: Dataset sample with metadata

        Returns:
            CWE category or None
        """
        # Check if sample has CWE information
        if hasattr(sample, 'metadata') and 'cwe' in sample.metadata:
            cwes = sample.metadata['cwe']
            if cwes and len(cwes) > 0:
                # Use first CWE
                cwe = cwes[0]
                return get_cwe_major_category(cwe)

        # Check if sample has target (benign/vulnerable)
        if hasattr(sample, 'target'):
            if sample.target == 0:
                return CWECategory.BENIGN
            # If vulnerable but no CWE, we can't determine category
            return None

        return None

    def _normalize_category(self, prediction: str) -> Optional[CWECategory]:
        """Normalize LLM prediction to a CWE category.

        Args:
            prediction: Raw LLM output

        Returns:
            Normalized CWE category or None
        """
        pred_lower = prediction.lower().strip()

        # Direct mapping
        category_keywords = {
            CWECategory.MEMORY: ['memory', 'buffer', 'overflow', 'use-after-free', 'null pointer'],
            CWECategory.INJECTION: ['injection', 'sql', 'xss', 'cross-site', 'command'],
            CWECategory.LOGIC: ['logic', 'authentication', 'race', 'authorization'],
            CWECategory.INPUT: ['input', 'validation', 'path', 'traversal'],
            CWECategory.CRYPTO: ['crypto', 'cryptographic', 'encryption', 'hash'],
            CWECategory.BENIGN: ['benign', 'safe', 'secure', 'no vulnerability'],
        }

        # Check for exact category name
        for category in CWECategory:
            if category.value.lower() in pred_lower:
                return category

        # Check for keywords
        for category, keywords in category_keywords.items():
            if any(kw in pred_lower for kw in keywords):
                return category

        # Unknown
        return None

    def evaluate_with_detailed_stats(
        self,
        prompt: str,
        sample_size: Optional[int] = None
    ) -> Dict:
        """Evaluate and return detailed statistics.

        Returns:
            Dictionary with detailed per-category statistics
        """
        stats = self.evaluate(prompt, sample_size)
        summary = stats.get_summary()

        # Add category-specific insights
        if 'category_stats' in summary:
            category_insights = {}
            for cat, cat_stats in summary['category_stats'].items():
                accuracy = cat_stats.get('accuracy', 0)
                error_rate = cat_stats.get('error_rate', 0)

                # Determine status
                if accuracy >= 0.8:
                    status = "Excellent"
                elif accuracy >= 0.6:
                    status = "Good"
                elif accuracy >= 0.4:
                    status = "Fair"
                else:
                    status = "Poor"

                category_insights[cat] = {
                    **cat_stats,
                    "status": status,
                    "needs_improvement": accuracy < 0.6
                }

            summary['category_insights'] = category_insights

        return summary
