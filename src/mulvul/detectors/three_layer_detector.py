"""Three-layer hierarchical detector for vulnerability classification.

Pipeline:
1. (Optional) Scale Enhancement
2. Layer 1: Classify to major category (Memory/Injection/Logic/Input/Crypto/Benign)
3. Layer 2: Classify to middle category (Buffer Overflow/SQL Injection/etc.)
4. Layer 3: Classify to specific CWE (CWE-120/CWE-89/etc.)
"""

from typing import Optional, Tuple, Dict, List
import logging

from ..llm.client import LLMClient
from ..prompts.hierarchical_three_layer import (
    ThreeLayerPromptSet,
    MajorCategory,
    MiddleCategory,
    MAJOR_TO_MIDDLE,
    MIDDLE_TO_CWE,
)

logger = logging.getLogger(__name__)


class ThreeLayerDetector:
    """Three-layer hierarchical vulnerability detector.

    Uses a cascade of prompts to progressively refine classification.
    """

    def __init__(
        self,
        prompt_set: ThreeLayerPromptSet,
        llm_client: LLMClient,
        use_scale_enhancement: bool = False
    ):
        """Initialize three-layer detector.

        Args:
            prompt_set: Complete prompt set for all layers
            llm_client: LLM client for detection
            use_scale_enhancement: Whether to use scale enhancement
        """
        self.prompt_set = prompt_set
        self.llm_client = llm_client
        self.use_scale_enhancement = use_scale_enhancement

    def detect(
        self,
        code: str,
        return_intermediate: bool = False
    ) -> Tuple[Optional[str], Dict]:
        """Detect vulnerability using three-layer classification.

        Args:
            code: Source code to analyze
            return_intermediate: Whether to return intermediate results

        Returns:
            Tuple of (final_cwe, details)
            details contains: {
                "layer1": major_category,
                "layer2": middle_category,
                "layer3": cwe,
                "enhanced_code": enhanced_code (if used),
                "confidence": confidence_score
            }
        """
        details = {}

        # Step 1: (Optional) Scale enhancement
        if self.use_scale_enhancement and self.prompt_set.scale_enhancement:
            try:
                enhanced_code = self._enhance_code(code)
                details["enhanced_code"] = enhanced_code
                analysis_input = enhanced_code
            except Exception as e:
                logger.warning(f"Scale enhancement failed: {e}, using original code")
                analysis_input = code
        else:
            analysis_input = code

        # Step 2: Layer 1 - Major category
        major_category = self._classify_layer1(analysis_input)
        details["layer1"] = major_category.value if major_category else "Unknown"

        if not major_category:
            logger.warning("Layer 1 classification failed")
            return (None, details)

        # Step 3: Layer 2 - Middle category
        middle_category = self._classify_layer2(analysis_input, major_category)
        details["layer2"] = middle_category.value if middle_category else "Unknown"

        if not middle_category:
            logger.warning(f"Layer 2 classification failed for {major_category.value}")
            return (None, details)

        # Step 4: Layer 3 - Specific CWE
        cwe = self._classify_layer3(analysis_input, middle_category)
        details["layer3"] = cwe if cwe else "Unknown"

        return (cwe, details)

    def detect_batch(
        self,
        codes: List[str],
        batch_size: int = 16
    ) -> List[Tuple[Optional[str], Dict]]:
        """Detect vulnerabilities for multiple code samples.

        Args:
            codes: List of code samples
            batch_size: Batch size for API calls

        Returns:
            List of (cwe, details) tuples
        """
        results = []

        for i in range(0, len(codes), batch_size):
            batch = codes[i:i + batch_size]

            for code in batch:
                try:
                    result = self.detect(code)
                    results.append(result)
                except Exception as e:
                    logger.error(f"Detection failed for sample: {e}")
                    results.append((None, {"error": str(e)}))

        return results

    def _enhance_code(self, code: str) -> str:
        """Enhance code using scale enhancement prompt.

        Args:
            code: Original code

        Returns:
            Enhanced code description
        """
        if not self.prompt_set.scale_enhancement:
            return code

        prompt = self.prompt_set.scale_enhancement.replace("{input}", code)

        try:
            response = self.llm_client.generate(prompt, temperature=0.3)
            return response.strip()
        except Exception as e:
            logger.error(f"Scale enhancement failed: {e}")
            return code

    def _classify_layer1(self, code: str) -> Optional[MajorCategory]:
        """Layer 1: Classify to major category.

        Args:
            code: Code to classify

        Returns:
            Major category or None
        """
        prompt = self.prompt_set.layer1_prompt.replace("{input}", code)

        try:
            response = self.llm_client.generate(prompt, temperature=0.1)
            return self._normalize_major_category(response)
        except Exception as e:
            logger.error(f"Layer 1 classification failed: {e}")
            return None

    def _classify_layer2(
        self,
        code: str,
        major_category: MajorCategory
    ) -> Optional[MiddleCategory]:
        """Layer 2: Classify to middle category.

        Args:
            code: Code to classify
            major_category: Major category from Layer 1

        Returns:
            Middle category or None
        """
        prompt_template = self.prompt_set.get_layer2_prompt(major_category)
        if not prompt_template:
            logger.warning(f"No Layer 2 prompt for {major_category.value}")
            return None

        prompt = prompt_template.replace("{input}", code)

        try:
            response = self.llm_client.generate(prompt, temperature=0.1)
            return self._normalize_middle_category(response, major_category)
        except Exception as e:
            logger.error(f"Layer 2 classification failed: {e}")
            return None

    def _classify_layer3(
        self,
        code: str,
        middle_category: MiddleCategory
    ) -> Optional[str]:
        """Layer 3: Classify to specific CWE.

        Args:
            code: Code to classify
            middle_category: Middle category from Layer 2

        Returns:
            CWE ID or None
        """
        prompt_template = self.prompt_set.get_layer3_prompt(middle_category)
        if not prompt_template:
            # Fallback to first CWE for this middle category
            cwes = MIDDLE_TO_CWE.get(middle_category, [])
            if cwes:
                logger.info(f"No Layer 3 prompt for {middle_category.value}, using first CWE: {cwes[0]}")
                return cwes[0]
            return None

        prompt = prompt_template.replace("{input}", code)

        try:
            response = self.llm_client.generate(prompt, temperature=0.1)
            return self._normalize_cwe(response, middle_category)
        except Exception as e:
            logger.error(f"Layer 3 classification failed: {e}")
            return None

    def _normalize_major_category(self, response: str) -> Optional[MajorCategory]:
        """Normalize LLM response to major category.

        Args:
            response: Raw LLM output

        Returns:
            Major category or None
        """
        response_lower = response.lower().strip()

        # Direct match (exact category name)
        for category in MajorCategory:
            if category.value.lower() == response_lower:
                return category

        # Check if category name appears in response
        for category in MajorCategory:
            if category.value.lower() in response_lower:
                return category

        # Extended keyword matching for long responses
        # Priority order: Injection > Input > Crypto > Logic > Memory > Benign
        keywords = {
            MajorCategory.INJECTION: [
                'injection', 'sql injection', 'command injection', 'xss',
                'cross-site scripting', 'ldap injection', 'xpath injection',
                'code injection', 'os command', 'shell injection',
                'select.*from', 'insert into', 'system(', 'popen(', 'exec('
            ],
            MajorCategory.INPUT: [
                'path traversal', 'directory traversal', 'format string',
                'improper input', 'input validation', '../', 'dot dot slash',
                'file path', 'uncontrolled format'
            ],
            MajorCategory.CRYPTO: [
                'crypto', 'cryptograph', 'encryption', 'weak cipher',
                'weak hash', 'md5', 'sha1', 'des', 'rc4', 'ecb mode',
                'insecure random', 'weak random', 'rand()', 'srand',
                'predictable', 'certificate'
            ],
            MajorCategory.LOGIC: [
                'logic', 'authentication', 'authorization', 'auth bypass',
                'race condition', 'toctou', 'time-of-check', 'concurrency',
                'access control', 'permission', 'session', 'token',
                'privilege', 'bypass'
            ],
            MajorCategory.MEMORY: [
                'memory', 'buffer overflow', 'buffer overrun', 'pointer',
                'null pointer', 'use-after-free', 'use after free',
                'double free', 'heap', 'stack', 'malloc', 'free',
                'allocation', 'dereference', 'out-of-bounds', 'oob',
                'integer overflow', 'memory leak', 'dangling'
            ],
            MajorCategory.BENIGN: [
                'benign', 'safe', 'secure', 'no vulnerabilit',
                'not vulnerable', 'does not contain', 'appears to be safe',
                'no security issue', 'no obvious vulnerabilit'
            ],
        }

        # Score each category (with priority weighting)
        priority_weights = {
            MajorCategory.INJECTION: 1.5,
            MajorCategory.INPUT: 1.4,
            MajorCategory.CRYPTO: 1.3,
            MajorCategory.LOGIC: 1.2,
            MajorCategory.MEMORY: 1.0,
            MajorCategory.BENIGN: 0.8,
        }

        scores = {}
        for category, kws in keywords.items():
            score = sum(1 for kw in kws if kw in response_lower)
            if score > 0:
                scores[category] = score * priority_weights.get(category, 1.0)

        # Return highest scoring category
        if scores:
            return max(scores, key=scores.get)

        return None

    def _normalize_middle_category(
        self,
        response: str,
        major_category: MajorCategory
    ) -> Optional[MiddleCategory]:
        """Normalize LLM response to middle category.

        Args:
            response: Raw LLM output
            major_category: Expected major category

        Returns:
            Middle category or None
        """
        response_lower = response.lower().strip()

        # Get valid middle categories for this major category
        valid_middles = MAJOR_TO_MIDDLE.get(major_category, [])

        # Direct match (exact category name)
        for middle in valid_middles:
            if middle.value.lower() == response_lower:
                return middle

        # Check if category name appears in response
        for middle in valid_middles:
            if middle.value.lower() in response_lower:
                return middle

        # Extended keyword matching for long responses
        keywords = {
            MiddleCategory.BUFFER_OVERFLOW: [
                'buffer overflow', 'buffer overrun', 'out-of-bounds write',
                'stack overflow', 'heap overflow', 'overflow'
            ],
            MiddleCategory.USE_AFTER_FREE: [
                'use after free', 'use-after-free', 'freed memory',
                'dangling pointer', 'double free'
            ],
            MiddleCategory.NULL_POINTER: [
                'null pointer', 'null dereference', 'nullptr',
                'null check', 'dereference'
            ],
            MiddleCategory.INTEGER_OVERFLOW: [
                'integer overflow', 'integer underflow', 'arithmetic overflow',
                'integer wrap'
            ],
            MiddleCategory.MEMORY_LEAK: [
                'memory leak', 'resource leak', 'not freed'
            ],
            MiddleCategory.SQL_INJECTION: [
                'sql injection', 'sql query', 'database injection'
            ],
            MiddleCategory.XSS: [
                'xss', 'cross-site scripting', 'script injection'
            ],
            MiddleCategory.COMMAND_INJECTION: [
                'command injection', 'os command', 'shell injection',
                'system call', 'exec'
            ],
            MiddleCategory.LDAP_INJECTION: [
                'ldap injection', 'ldap query'
            ],
            MiddleCategory.AUTH_BYPASS: [
                'authentication bypass', 'auth bypass', 'login bypass',
                'authentication', 'authorization bypass'
            ],
            MiddleCategory.RACE_CONDITION: [
                'race condition', 'race', 'toctou', 'time-of-check'
            ],
            MiddleCategory.INSECURE_DEFAULTS: [
                'insecure default', 'default configuration', 'misconfiguration'
            ],
            MiddleCategory.PATH_TRAVERSAL: [
                'path traversal', 'directory traversal', '../', 'dot dot'
            ],
            MiddleCategory.INPUT_VALIDATION: [
                'input validation', 'improper validation', 'unvalidated input'
            ],
            MiddleCategory.UNCONTROLLED_FORMAT: [
                'format string', 'printf', 'uncontrolled format'
            ],
            MiddleCategory.WEAK_CRYPTO: [
                'weak crypto', 'weak encryption', 'weak cipher',
                'md5', 'sha1', 'des', 'rc4'
            ],
            MiddleCategory.INSECURE_RANDOM: [
                'insecure random', 'weak random', 'predictable random',
                'rand()', 'srand'
            ],
            MiddleCategory.SAFE_CODE: [
                'safe', 'secure', 'no vulnerabilit', 'benign'
            ],
        }

        # Score each valid middle category
        scores = {}
        for middle in valid_middles:
            kws = keywords.get(middle, [])
            score = sum(1 for kw in kws if kw in response_lower)
            if score > 0:
                scores[middle] = score

        # Return highest scoring category
        if scores:
            return max(scores, key=scores.get)

        # Fallback: return first valid middle category
        if valid_middles:
            logger.warning(f"Could not normalize '{response[:50]}...', using first middle category")
            return valid_middles[0]

        return None

    def _normalize_cwe(
        self,
        response: str,
        middle_category: MiddleCategory
    ) -> Optional[str]:
        """Normalize LLM response to CWE ID.

        Args:
            response: Raw LLM output
            middle_category: Expected middle category

        Returns:
            CWE ID or None
        """
        response_upper = response.upper().strip()

        # Get valid CWEs for this middle category
        valid_cwes = MIDDLE_TO_CWE.get(middle_category, [])

        # Direct CWE-XXX match
        for cwe in valid_cwes:
            if cwe in response_upper:
                return cwe

        # Extract CWE-XXX pattern
        import re
        match = re.search(r'CWE-\d+', response_upper)
        if match:
            cwe = match.group(0)
            if cwe in valid_cwes:
                return cwe

        # Fallback: return first valid CWE
        if valid_cwes:
            logger.warning(f"Could not extract CWE from '{response}', using first CWE")
            return valid_cwes[0]

        return None


class ThreeLayerEvaluator:
    """Evaluator for three-layer detection system with comprehensive metrics."""

    def __init__(
        self,
        detector: ThreeLayerDetector,
        dataset
    ):
        """Initialize evaluator.

        Args:
            detector: Three-layer detector
            dataset: Dataset with ground truth CWE labels
        """
        self.detector = detector
        self.dataset = dataset

    def evaluate(
        self,
        sample_size: Optional[int] = None,
        verbose: bool = False
    ) -> Dict:
        """Evaluate detector on dataset with comprehensive metrics.

        Args:
            sample_size: Optional number of samples
            verbose: Whether to print detailed metrics

        Returns:
            Dictionary with evaluation metrics including Macro/Weighted/Micro F1
        """
        from ..prompts.hierarchical_three_layer import get_full_path
        from ..evaluators.multiclass_metrics import MultiClassMetrics

        samples = self.dataset.get_samples(sample_size)

        # Initialize metrics for each layer
        layer1_metrics = MultiClassMetrics()
        layer2_metrics = MultiClassMetrics()
        layer3_metrics = MultiClassMetrics()

        stats = {
            "total": 0,
            "full_path_correct": 0,
        }

        results = []

        for sample in samples:
            # Get ground truth
            actual_cwe = self._get_sample_cwe(sample)
            if not actual_cwe:
                continue

            actual_major, actual_middle, _ = get_full_path(actual_cwe)

            # Skip if path is incomplete
            if not actual_major or not actual_middle:
                continue

            # Detect
            predicted_cwe, details = self.detector.detect(sample.input_text)

            stats["total"] += 1

            # Add predictions to metrics
            layer1_metrics.add_prediction(
                details.get("layer1", "Unknown"),
                actual_major.value
            )

            layer2_metrics.add_prediction(
                details.get("layer2", "Unknown"),
                actual_middle.value
            )

            layer3_metrics.add_prediction(
                predicted_cwe or "Unknown",
                actual_cwe
            )

            # Check full path
            if (details.get("layer1") == actual_major.value and
                details.get("layer2") == actual_middle.value and
                predicted_cwe == actual_cwe):
                stats["full_path_correct"] += 1

            results.append({
                "actual_major": actual_major.value,
                "actual_middle": actual_middle.value,
                "actual_cwe": actual_cwe,
                "predicted_major": details.get("layer1", "Unknown"),
                "predicted_middle": details.get("layer2", "Unknown"),
                "predicted_cwe": predicted_cwe or "Unknown",
            })

        # Generate comprehensive metrics
        metrics = {
            "total_samples": stats["total"],

            # Layer 1 metrics
            "layer1": {
                "accuracy": round(layer1_metrics.accuracy, 4),
                "macro_f1": round(layer1_metrics.compute_macro_f1(), 4),
                "weighted_f1": round(layer1_metrics.compute_weighted_f1(), 4),
                "micro_f1": round(layer1_metrics.compute_micro_f1(), 4),
                "macro_precision": round(layer1_metrics.compute_macro_precision(), 4),
                "macro_recall": round(layer1_metrics.compute_macro_recall(), 4),
            },

            # Layer 2 metrics
            "layer2": {
                "accuracy": round(layer2_metrics.accuracy, 4),
                "macro_f1": round(layer2_metrics.compute_macro_f1(), 4),
                "weighted_f1": round(layer2_metrics.compute_weighted_f1(), 4),
                "micro_f1": round(layer2_metrics.compute_micro_f1(), 4),
                "macro_precision": round(layer2_metrics.compute_macro_precision(), 4),
                "macro_recall": round(layer2_metrics.compute_macro_recall(), 4),
            },

            # Layer 3 metrics
            "layer3": {
                "accuracy": round(layer3_metrics.accuracy, 4),
                "macro_f1": round(layer3_metrics.compute_macro_f1(), 4),
                "weighted_f1": round(layer3_metrics.compute_weighted_f1(), 4),
                "micro_f1": round(layer3_metrics.compute_micro_f1(), 4),
                "macro_precision": round(layer3_metrics.compute_macro_precision(), 4),
                "macro_recall": round(layer3_metrics.compute_macro_recall(), 4),
            },

            # Full path accuracy
            "full_path_accuracy": round(
                stats["full_path_correct"] / stats["total"] if stats["total"] > 0 else 0,
                4
            ),

            # Per-class metrics for each layer
            "layer1_per_class": layer1_metrics.get_per_class_metrics(),
            "layer2_per_class": layer2_metrics.get_per_class_metrics(),
            "layer3_per_class": layer3_metrics.get_per_class_metrics(),

            # Sample results
            "sample_results": results[:10],
        }

        # Print detailed report if verbose
        if verbose:
            print("\n" + "=" * 70)
            print("EVALUATION RESULTS")
            print("=" * 70)

            print(f"\nTotal Samples: {metrics['total_samples']}")
            print(f"Full Path Accuracy: {metrics['full_path_accuracy']:.4f}")

            print("\n" + "-" * 70)
            print("Layer 1 (Major Category)")
            print("-" * 70)
            self._print_layer_metrics(metrics["layer1"])

            print("\n" + "-" * 70)
            print("Layer 2 (Middle Category)")
            print("-" * 70)
            self._print_layer_metrics(metrics["layer2"])

            print("\n" + "-" * 70)
            print("Layer 3 (CWE)")
            print("-" * 70)
            self._print_layer_metrics(metrics["layer3"])

            print("\n" + "=" * 70)
            print("💡 推荐关注指标: Macro-F1")
            print("   原因: 漏洞检测中类别不平衡，Macro-F1确保所有类别都被重视")
            print("=" * 70)

        return metrics

    def _print_layer_metrics(self, layer_metrics: Dict):
        """打印单层的指标"""
        print(f"  Accuracy:        {layer_metrics['accuracy']:.4f}")
        print(f"  Macro-F1:        {layer_metrics['macro_f1']:.4f} ⭐ (推荐)")
        print(f"  Weighted-F1:     {layer_metrics['weighted_f1']:.4f}")
        print(f"  Micro-F1:        {layer_metrics['micro_f1']:.4f}")
        print(f"  Macro-Precision: {layer_metrics['macro_precision']:.4f}")
        print(f"  Macro-Recall:    {layer_metrics['macro_recall']:.4f}")

    def _get_sample_cwe(self, sample) -> Optional[str]:
        """Extract CWE from sample.

        Args:
            sample: Dataset sample

        Returns:
            CWE ID or None
        """
        if hasattr(sample, 'metadata') and 'cwe' in sample.metadata:
            cwes = sample.metadata['cwe']
            if cwes and len(cwes) > 0:
                return cwes[0]
        return None
