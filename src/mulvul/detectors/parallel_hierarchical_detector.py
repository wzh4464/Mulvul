"""Parallel hierarchical vulnerability detector with multi-layer classification.

Implements a three-layer parallel detection system:
  Layer 1: Parallel classification into major vulnerability categories (top-k selection)
  Layer 2: Parallel sub-classification within selected major categories
  Layer 3: CWE-specific classification

Supports optional code enhancement via Comment4Vul or similar enhancers.
"""

import asyncio
import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Tuple, Any, runtime_checkable

from ..llm.async_client import AsyncLLMClient
from ..rag.retriever import CodeSimilarityRetriever, RetrievalResult
from ..prompts.hierarchical_three_layer import (
    MajorCategory,
    MiddleCategory,
    MAJOR_TO_MIDDLE,
    MIDDLE_TO_CWE,
    ThreeLayerPromptSet,
)
from .scoring import ScoredPrediction, DetectionPath, SelectionStrategy, MaxConfidenceSelection


logger = logging.getLogger(__name__)


def _insert_rag_before_code_section(prompt: str, rag_text: str) -> str:
    """Insert RAG context before the 'Code to analyze:' line in a prompt.

    If the marker line is not found, prepend to the whole prompt as fallback.
    """
    marker = "Code to analyze:"
    idx = prompt.find(marker)
    if idx != -1:
        return prompt[:idx] + rag_text + prompt[idx:]
    # Fallback: prepend
    return rag_text + prompt


@runtime_checkable
class CodeEnhancer(Protocol):
    """Protocol for code enhancement (e.g., Comment4Vul).
    
    Code enhancers add analysis comments or annotations to source code
    to improve vulnerability detection.
    """
    
    def enhance(self, code: str) -> str:
        """Synchronously enhance code with analysis comments.
        
        Args:
            code: Original source code
            
        Returns:
            Enhanced code with added comments/annotations
        """
        ...
    
    async def enhance_async(self, code: str) -> str:
        """Asynchronously enhance code with analysis comments.
        
        Args:
            code: Original source code
            
        Returns:
            Enhanced code with added comments/annotations
        """
        ...


class NoOpEnhancer:
    """Default no-op enhancer that returns code unchanged."""
    
    def enhance(self, code: str) -> str:
        return code
    
    async def enhance_async(self, code: str) -> str:
        return code


@dataclass
class HierarchicalPromptSet:
    """Complete prompt set for parallel hierarchical detection.
    
    Organizes prompts by layer with support for trainable sections.
    
    Attributes:
        layer1_prompts: Mapping of MajorCategory → prompt string
        layer2_prompts: Nested mapping of MajorCategory → MiddleCategory → prompt
        layer3_prompts: Nested mapping of MiddleCategory → CWE → prompt
        shared_structure: Common output format constraints
        trainable_markers: Tuple of (start, end) markers for trainable sections
    """
    layer1_prompts: Dict[str, str] = field(default_factory=dict)
    layer2_prompts: Dict[str, Dict[str, str]] = field(default_factory=dict)
    layer3_prompts: Dict[str, Dict[str, str]] = field(default_factory=dict)
    shared_structure: str = ""
    trainable_markers: Tuple[str, str] = ("{{TRAINABLE_START}}", "{{TRAINABLE_END}}")
    
    @classmethod
    def from_three_layer_set(cls, prompt_set: ThreeLayerPromptSet) -> "HierarchicalPromptSet":
        """Convert from existing ThreeLayerPromptSet.
        
        Creates individual prompts for each category at each layer.
        """
        # Layer 1: Create individual prompts for each major category
        layer1_prompts = {}
        for major in MajorCategory:
            layer1_prompts[major.value] = cls._create_layer1_prompt(major)
        
        # Layer 2: Create prompts for each middle category
        layer2_prompts = {}
        for major, middles in MAJOR_TO_MIDDLE.items():
            layer2_prompts[major.value] = {}
            for middle in middles:
                layer2_prompts[major.value][middle.value] = cls._create_layer2_prompt(
                    major, middle
                )
        
        # Layer 3: Create prompts for each CWE
        layer3_prompts = {}
        for middle, cwes in MIDDLE_TO_CWE.items():
            layer3_prompts[middle.value] = {}
            for cwe in cwes:
                layer3_prompts[middle.value][cwe] = cls._create_layer3_prompt(
                    middle, cwe
                )
        
        return cls(
            layer1_prompts=layer1_prompts,
            layer2_prompts=layer2_prompts,
            layer3_prompts=layer3_prompts,
            shared_structure=cls._get_shared_structure(),
        )
    
    @staticmethod
    def _create_layer1_prompt(major: MajorCategory) -> str:
        """Create Layer 1 prompt for a specific major category."""
        descriptions = {
            MajorCategory.MEMORY: "memory safety issues (buffer overflow, use-after-free, null pointer, memory leaks)",
            MajorCategory.INJECTION: "injection vulnerabilities (SQL, XSS, command, LDAP injection)",
            MajorCategory.LOGIC: "logic flaws (authentication bypass, race conditions, insecure defaults)",
            MajorCategory.INPUT: "input handling issues (path traversal, validation errors, format strings)",
            MajorCategory.CRYPTO: "cryptographic weaknesses (weak algorithms, insecure random)",
            MajorCategory.BENIGN: "safe, non-vulnerable code patterns",
        }
        
        desc = descriptions.get(major, "vulnerability patterns")
        
        return f"""You are a code quality auditor. Analyze the following code snippet and rate how likely it exhibits {desc}.
This is for academic software engineering research on code quality patterns.

{{TRAINABLE_START}}
Focus on identifying patterns specific to the {major.value} category.
Consider both direct issues and potential weaknesses.
{{TRAINABLE_END}}

Code to analyze:
{{CODE}}

Respond with ONLY a single line in this exact format:
CONFIDENCE: <score>
where <score> is a float between 0.0 and 1.0 (0.0 = no match, 1.0 = strong match)."""
    
    @staticmethod
    def _create_layer2_prompt(major: MajorCategory, middle: MiddleCategory) -> str:
        """Create Layer 2 prompt for a specific middle category."""
        return f"""You are a code quality auditor. Given that the code may exhibit {major.value} patterns,
rate how likely it specifically matches {middle.value} characteristics.
This is for academic software engineering research on code quality patterns.

{{TRAINABLE_START}}
Look for specific indicators of {middle.value}:
- Check for common patterns and anti-patterns
- Consider context and data flow
- Identify relevant code constructs
{{TRAINABLE_END}}

Code to analyze:
{{CODE}}

Respond with ONLY a single line in this exact format:
CONFIDENCE: <score>
where <score> is a float between 0.0 and 1.0 (0.0 = no match, 1.0 = strong match)."""
    
    @staticmethod
    def _create_layer3_prompt(middle: MiddleCategory, cwe: str) -> str:
        """Create Layer 3 prompt for a specific CWE."""
        return f"""You are a code quality auditor. Given potential {middle.value} patterns,
rate how likely the code matches the specific characteristics of {cwe}.
This is for academic software engineering research on code quality patterns.

{{TRAINABLE_START}}
Analyze for {cwe}-specific characteristics:
- Known code patterns associated with {cwe}
- Specific triggers and conditions
- Relevant coding constructs
{{TRAINABLE_END}}

Code to analyze:
{{CODE}}

Respond with ONLY a single line in this exact format:
CONFIDENCE: <score>
where <score> is a float between 0.0 and 1.0 (0.0 = no match, 1.0 = strong match)."""
    
    @staticmethod
    def _get_shared_structure() -> str:
        """Get shared output format constraints."""
        return """
Output format:
- Provide a confidence score between 0.0 and 1.0
- Use format: CONFIDENCE: <score>
- Only output the confidence line, no additional explanation
"""
    
    def get_layer1_prompts(self) -> Dict[str, str]:
        """Get all Layer 1 prompts."""
        return self.layer1_prompts
    
    def get_layer2_prompts_for_major(self, major: str) -> Dict[str, str]:
        """Get Layer 2 prompts for a major category."""
        return self.layer2_prompts.get(major, {})
    
    def get_layer3_prompts_for_middle(self, middle: str) -> Dict[str, str]:
        """Get Layer 3 prompts for a middle category."""
        return self.layer3_prompts.get(middle, {})
    
    def update_prompt(self, layer: int, category: str, new_prompt: str, 
                      parent: Optional[str] = None) -> None:
        """Update a specific prompt (for meta-learning).
        
        Args:
            layer: Layer number (1, 2, or 3)
            category: Category name
            new_prompt: New prompt content
            parent: Parent category (required for layer 2 and 3)
        """
        if layer == 1:
            self.layer1_prompts[category] = new_prompt
        elif layer == 2:
            if parent is None:
                raise ValueError("Parent required for layer 2")
            if parent not in self.layer2_prompts:
                self.layer2_prompts[parent] = {}
            self.layer2_prompts[parent][category] = new_prompt
        elif layer == 3:
            if parent is None:
                raise ValueError("Parent required for layer 3")
            if parent not in self.layer3_prompts:
                self.layer3_prompts[parent] = {}
            self.layer3_prompts[parent][category] = new_prompt


@dataclass
class ParallelDetectorConfig:
    """Configuration for parallel hierarchical detector.

    Attributes:
        layer1_top_k: Number of top categories to select from Layer 1
        layer2_top_k: Number of top categories to select from Layer 2
        layer3_top_k: Number of top CWEs to select from Layer 3
        max_concurrent_requests: Maximum concurrent LLM requests
        default_confidence: Default confidence for parse failures
        enable_enhancement: Whether to use code enhancement
        enable_rag: Whether to enable RAG-based prompt enhancement
        rag_top_k: Number of RAG examples to retrieve per layer
        rag_retriever_type: Type of retriever ("lexical" or "embedding")
    """
    layer1_top_k: int = 2
    layer2_top_k: int = 2
    layer3_top_k: int = 1
    max_concurrent_requests: int = 20
    default_confidence: float = 0.0
    enable_enhancement: bool = True
    enable_rag: bool = False
    rag_top_k: int = 2
    rag_retriever_type: str = "lexical"


class ParallelHierarchicalDetector:
    """Parallel hierarchical vulnerability detector.
    
    Performs three-layer detection with parallel execution at each layer:
    1. Layer 1: Classify into major categories, select top-k
    2. Layer 2: For each selected major, classify into middle categories
    3. Layer 3: For each selected middle, classify into specific CWEs
    
    Results are aggregated using a configurable selection strategy.
    """
    
    def __init__(
        self,
        llm_client: AsyncLLMClient,
        prompt_set: HierarchicalPromptSet,
        config: Optional[ParallelDetectorConfig] = None,
        enhancer: Optional[CodeEnhancer] = None,
        selection_strategy: Optional[SelectionStrategy] = None,
        retriever: Optional[CodeSimilarityRetriever] = None,
    ):
        """Initialize the detector.

        Args:
            llm_client: Async LLM client for API calls
            prompt_set: Hierarchical prompt set
            config: Detector configuration
            enhancer: Optional code enhancer (e.g., Comment4Vul)
            selection_strategy: Strategy for final path selection
            retriever: Optional RAG retriever for prompt enhancement

        Raises:
            ValueError: If config.enable_rag is True but no retriever is provided
        """
        self.llm_client = llm_client
        self.prompt_set = prompt_set
        self.config = config or ParallelDetectorConfig()
        self.enhancer = enhancer or NoOpEnhancer()
        self.selection_strategy = selection_strategy or MaxConfidenceSelection()
        self.retriever = retriever

        if self.config.enable_rag and self.retriever is None:
            raise ValueError("enable_rag=True requires a retriever to be provided")

        # Semaphore for controlling concurrent requests
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)

        # Per-detect RAG metadata and cache
        self._last_rag_metadata: Dict[str, Any] = {}
        self._rag_cache: Dict[Tuple[str, int, Optional[str]], RetrievalResult] = {}
    
    def _code_hash(self, code: str) -> str:
        """Compute a short hash of code for caching."""
        return hashlib.md5(code.encode("utf-8", errors="replace")).hexdigest()[:16]

    async def _retrieve_async(
        self,
        query_code: str,
        layer: int,
        category_name: Optional[str] = None,
    ) -> Optional[RetrievalResult]:
        """Retrieve RAG examples asynchronously, with per-detect caching.

        Args:
            query_code: Code to find similar examples for
            layer: Detection layer (1, 2, or 3)
            category_name: Category name for layer 2/3 retrieval

        Returns:
            RetrievalResult or None if RAG disabled or retrieval fails
        """
        if not self.config.enable_rag or self.retriever is None:
            return None

        cache_key = (self._code_hash(query_code), layer, category_name)
        if cache_key in self._rag_cache:
            return self._rag_cache[cache_key]

        try:
            if layer == 1:
                result = await asyncio.to_thread(
                    self.retriever.retrieve_for_major_category,
                    query_code,
                    self.config.rag_top_k,
                )
            elif layer == 2:
                result = await asyncio.to_thread(
                    self.retriever.retrieve_for_middle_category_by_name,
                    query_code,
                    category_name or "",
                    self.config.rag_top_k,
                )
            elif layer == 3:
                result = await asyncio.to_thread(
                    self.retriever.retrieve_for_cwe_by_name,
                    query_code,
                    category_name or "",
                    self.config.rag_top_k,
                )
            else:
                return None

            self._rag_cache[cache_key] = result
            return result
        except Exception as e:
            logger.warning(f"RAG retrieval failed for layer {layer}: {e}")
            empty = RetrievalResult(
                examples=[], formatted_text="", similarity_scores=[],
                debug_info={"error": str(e), "pool_size": 0, "num_retrieved": 0},
            )
            self._rag_cache[cache_key] = empty
            return empty

    async def detect_async(self, code: str) -> List[DetectionPath]:
        """Perform hierarchical detection on code.

        Args:
            code: Source code to analyze

        Returns:
            List of detection paths sorted by confidence
        """
        # Reset per-detect state
        self._last_rag_metadata = {}
        self._rag_cache = {}

        # Step 1: Optionally enhance code
        if self.config.enable_enhancement:
            enhanced_code = await self.enhancer.enhance_async(code)
        else:
            enhanced_code = code

        # Step 2: Layer 1 - Parallel classification into major categories
        layer1_predictions = await self._classify_layer1_parallel(enhanced_code)

        # Select top-k from Layer 1
        top_layer1 = sorted(
            layer1_predictions,
            key=lambda p: p.confidence,
            reverse=True
        )[:self.config.layer1_top_k]

        logger.debug(f"Layer 1 top-{self.config.layer1_top_k}: {[p.category for p in top_layer1]}")

        # Step 3: Layer 2 - Parallel classification for each selected major category
        layer2_predictions = await self._classify_layer2_parallel(
            enhanced_code,
            [p.category for p in top_layer1]
        )

        # Step 4: Layer 3 - Parallel CWE classification
        layer3_predictions = await self._classify_layer3_parallel(
            enhanced_code,
            layer2_predictions
        )

        # Step 5: Build detection paths
        paths = self._build_detection_paths(
            layer1_predictions,
            layer2_predictions,
            layer3_predictions
        )

        # Step 6: Inject RAG metadata into paths
        if self._last_rag_metadata:
            for path in paths:
                path.metadata["rag"] = self._last_rag_metadata

        # Step 7: Apply selection strategy
        selected_paths = self.selection_strategy.select(paths, top_k=self.config.layer3_top_k)

        return selected_paths
    
    def detect(self, code: str) -> List[DetectionPath]:
        """Synchronous wrapper for detect_async."""
        return asyncio.run(self.detect_async(code))
    
    async def detect_batch_async(
        self, 
        codes: List[str],
        show_progress: bool = True
    ) -> List[List[DetectionPath]]:
        """Perform detection on multiple code samples.
        
        Args:
            codes: List of code samples
            show_progress: Whether to log progress
            
        Returns:
            List of detection results for each code sample
        """
        results = []
        for i, code in enumerate(codes):
            result = await self.detect_async(code)
            results.append(result)
            
            if show_progress and (i + 1) % 10 == 0:
                logger.info(f"Processed {i + 1}/{len(codes)} samples")
        
        return results
    
    async def _classify_layer1_parallel(
        self,
        code: str
    ) -> List[ScoredPrediction]:
        """Classify code into major categories in parallel.

        Args:
            code: Enhanced source code

        Returns:
            List of scored predictions for each major category
        """
        prompts = self.prompt_set.get_layer1_prompts()
        categories = list(prompts.keys())

        # RAG: retrieve once for all Layer 1 prompts
        rag_prefix = ""
        if self.config.enable_rag:
            rag_result = await self._retrieve_async(code, layer=1)
            if rag_result and rag_result.formatted_text:
                rag_prefix = rag_result.formatted_text + "\n\n"
                self._last_rag_metadata["layer1"] = {
                    "num_examples": len(rag_result.examples),
                    "debug_info": rag_result.debug_info,
                }

        # Prepare prompts with code (and optional RAG context before the Code section)
        filled_prompts = []
        for prompt in prompts.values():
            filled = prompt.replace("{CODE}", code).replace("{{CODE}}", code)
            if rag_prefix:
                # Insert RAG context before "Code to analyze:" line
                filled = _insert_rag_before_code_section(filled, rag_prefix)
            filled_prompts.append(filled)

        # Execute in parallel
        responses = await self._batch_generate_with_semaphore(filled_prompts)

        # Parse responses
        predictions = []
        for category, response in zip(categories, responses):
            confidence = self._parse_confidence(response)
            predictions.append(ScoredPrediction(
                category=category,
                confidence=confidence,
                layer=1,
                raw_response=response
            ))

        return predictions
    
    async def _classify_layer2_parallel(
        self,
        code: str,
        selected_majors: List[str]
    ) -> List[ScoredPrediction]:
        """Classify code into middle categories for selected majors.

        Args:
            code: Enhanced source code
            selected_majors: List of selected major category names

        Returns:
            List of scored predictions for middle categories
        """
        # RAG: retrieve per selected major in parallel
        rag_prefixes: Dict[str, str] = {}
        if self.config.enable_rag:
            rag_tasks = {
                major: self._retrieve_async(code, layer=2, category_name=major)
                for major in selected_majors
            }
            rag_results = await asyncio.gather(*rag_tasks.values())
            layer2_rag_meta = {}
            for major, result in zip(rag_tasks.keys(), rag_results):
                if result and result.formatted_text:
                    rag_prefixes[major] = result.formatted_text + "\n\n"
                    layer2_rag_meta[major] = {
                        "num_examples": len(result.examples),
                        "debug_info": result.debug_info,
                    }
            if layer2_rag_meta:
                self._last_rag_metadata["layer2"] = layer2_rag_meta

        all_prompts = []
        all_categories = []
        parent_map = []

        for major in selected_majors:
            prefix = rag_prefixes.get(major, "")
            layer2_prompts = self.prompt_set.get_layer2_prompts_for_major(major)
            for middle, prompt in layer2_prompts.items():
                filled = prompt.replace("{CODE}", code).replace("{{CODE}}", code)
                if prefix:
                    filled = _insert_rag_before_code_section(filled, prefix)
                all_prompts.append(filled)
                all_categories.append(middle)
                parent_map.append(major)

        if not all_prompts:
            return []

        # Execute in parallel
        responses = await self._batch_generate_with_semaphore(all_prompts)

        # Parse responses
        predictions = []
        for category, parent, response in zip(all_categories, parent_map, responses):
            confidence = self._parse_confidence(response)
            predictions.append(ScoredPrediction(
                category=category,
                confidence=confidence,
                layer=2,
                parent_category=parent,
                raw_response=response
            ))

        return predictions
    
    async def _classify_layer3_parallel(
        self,
        code: str,
        layer2_predictions: List[ScoredPrediction]
    ) -> List[ScoredPrediction]:
        """Classify code into specific CWEs for relevant middle categories.

        Args:
            code: Enhanced source code
            layer2_predictions: Predictions from Layer 2

        Returns:
            List of scored predictions for CWEs
        """
        # Select top middle categories based on confidence
        top_middles = sorted(
            layer2_predictions,
            key=lambda p: p.confidence,
            reverse=True
        )[:self.config.layer2_top_k * self.config.layer1_top_k]  # Account for multiple majors

        # RAG: retrieve per selected middle in parallel
        selected_middle_names = list({pred.category for pred in top_middles})
        rag_prefixes: Dict[str, str] = {}
        if self.config.enable_rag and selected_middle_names:
            rag_tasks = {
                middle: self._retrieve_async(code, layer=3, category_name=middle)
                for middle in selected_middle_names
            }
            rag_results = await asyncio.gather(*rag_tasks.values())
            layer3_rag_meta = {}
            for middle, result in zip(rag_tasks.keys(), rag_results):
                if result and result.formatted_text:
                    rag_prefixes[middle] = result.formatted_text + "\n\n"
                    layer3_rag_meta[middle] = {
                        "num_examples": len(result.examples),
                        "debug_info": result.debug_info,
                    }
            if layer3_rag_meta:
                self._last_rag_metadata["layer3"] = layer3_rag_meta

        all_prompts = []
        all_cwes = []
        parent_map = []

        for pred in top_middles:
            prefix = rag_prefixes.get(pred.category, "")
            layer3_prompts = self.prompt_set.get_layer3_prompts_for_middle(pred.category)
            for cwe, prompt in layer3_prompts.items():
                filled = prompt.replace("{CODE}", code).replace("{{CODE}}", code)
                if prefix:
                    filled = _insert_rag_before_code_section(filled, prefix)
                all_prompts.append(filled)
                all_cwes.append(cwe)
                parent_map.append(pred.category)

        if not all_prompts:
            return []

        # Execute in parallel
        responses = await self._batch_generate_with_semaphore(all_prompts)

        # Parse responses
        predictions = []
        for cwe, parent, response in zip(all_cwes, parent_map, responses):
            confidence = self._parse_confidence(response)
            predictions.append(ScoredPrediction(
                category=cwe,
                confidence=confidence,
                layer=3,
                parent_category=parent,
                raw_response=response
            ))

        return predictions
    
    async def _batch_generate_with_semaphore(
        self, 
        prompts: List[str]
    ) -> List[str]:
        """Execute batch generation with semaphore control.
        
        Args:
            prompts: List of prompts to process
            
        Returns:
            List of LLM responses
        """
        async def generate_one(prompt: str) -> str:
            async with self._semaphore:
                return await self.llm_client.generate_async(prompt)
        
        tasks = [generate_one(p) for p in prompts]
        return await asyncio.gather(*tasks, return_exceptions=False)
    
    def _parse_confidence(self, response: str) -> float:
        """Parse confidence score from LLM response.

        Handles verbose GPT-4o responses that may contain analysis text
        alongside or instead of the expected CONFIDENCE format.

        Args:
            response: Raw LLM response

        Returns:
            Parsed confidence score (0.0 to 1.0)
        """
        if not response or response == "error":
            return self.config.default_confidence

        # Phase 1: Exact pattern matches (best quality)
        exact_patterns = [
            r"CONFIDENCE:\s*([0-9]*\.?[0-9]+)",
            r"confidence:\s*([0-9]*\.?[0-9]+)",
            r"Score:\s*([0-9]*\.?[0-9]+)",
        ]
        for pattern in exact_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                try:
                    score = float(match.group(1))
                    if score > 1.0:
                        score = score / 100.0
                    return max(0.0, min(1.0, score))
                except ValueError:
                    continue

        # Phase 2: Look for decimal numbers (0.xx) anywhere in the response
        # These are likely confidence/probability values
        decimal_matches = re.findall(r'\b(0\.\d+)\b', response)
        if decimal_matches:
            # Take the last one (most likely to be the final answer)
            try:
                score = float(decimal_matches[-1])
                return max(0.0, min(1.0, score))
            except ValueError:
                pass

        # Phase 3: Look for percentage-like values (e.g., "85%", "high (70%)")
        pct_match = re.search(r'(\d{1,3})\s*%', response)
        if pct_match:
            try:
                score = float(pct_match.group(1)) / 100.0
                return max(0.0, min(1.0, score))
            except ValueError:
                pass

        # Phase 4: Verbal confidence indicators
        response_lower = response.lower()
        if any(w in response_lower for w in ['high confidence', 'very likely', 'clearly', 'definitely']):
            return 0.85
        if any(w in response_lower for w in ['moderate', 'possibly', 'may contain', 'could be']):
            return 0.55
        if any(w in response_lower for w in ['low confidence', 'unlikely', 'no evidence', 'does not', 'no vulnerability', 'benign', 'safe']):
            return 0.15

        # Phase 5: Number at end of response
        end_match = re.search(r'(\d+\.?\d*)\s*$', response)
        if end_match:
            try:
                score = float(end_match.group(1))
                if score > 1.0:
                    score = score / 100.0
                return max(0.0, min(1.0, score))
            except ValueError:
                pass

        logger.warning(f"Could not parse confidence from response: {response[:100]}")
        return self.config.default_confidence
    
    def _build_detection_paths(
        self,
        layer1: List[ScoredPrediction],
        layer2: List[ScoredPrediction],
        layer3: List[ScoredPrediction]
    ) -> List[DetectionPath]:
        """Build complete detection paths from layer predictions.
        
        Args:
            layer1: Layer 1 predictions
            layer2: Layer 2 predictions
            layer3: Layer 3 predictions
            
        Returns:
            List of complete detection paths
        """
        # Create lookup maps
        l1_map = {p.category: p for p in layer1}
        l2_map = {p.category: p for p in layer2}
        l3_by_parent = {}
        for p in layer3:
            if p.parent_category not in l3_by_parent:
                l3_by_parent[p.parent_category] = []
            l3_by_parent[p.parent_category].append(p)
        
        paths = []
        
        # Build paths from Layer 3 back to Layer 1
        for l3_pred in layer3:
            middle = l3_pred.parent_category
            l2_pred = l2_map.get(middle)
            
            if l2_pred is None:
                continue
            
            major = l2_pred.parent_category
            l1_pred = l1_map.get(major)
            
            if l1_pred is None:
                continue
            
            path = DetectionPath(
                layer1_category=major,
                layer1_confidence=l1_pred.confidence,
                layer2_category=middle,
                layer2_confidence=l2_pred.confidence,
                layer3_cwe=l3_pred.category,
                layer3_confidence=l3_pred.confidence,
                metadata={
                    "layer1_raw": l1_pred.raw_response,
                    "layer2_raw": l2_pred.raw_response,
                    "layer3_raw": l3_pred.raw_response,
                }
            )
            paths.append(path)
        
        # Also include Layer 2 paths without Layer 3 (for categories without CWEs)
        for l2_pred in layer2:
            if l2_pred.category in l3_by_parent:
                continue  # Already handled via Layer 3
            
            major = l2_pred.parent_category
            l1_pred = l1_map.get(major)
            
            if l1_pred is None:
                continue
            
            path = DetectionPath(
                layer1_category=major,
                layer1_confidence=l1_pred.confidence,
                layer2_category=l2_pred.category,
                layer2_confidence=l2_pred.confidence,
                metadata={
                    "layer1_raw": l1_pred.raw_response,
                    "layer2_raw": l2_pred.raw_response,
                }
            )
            paths.append(path)
        
        return paths


# Factory function for creating detector with default configuration
def create_parallel_detector(
    llm_client: AsyncLLMClient,
    prompt_set: Optional[ThreeLayerPromptSet] = None,
    enhancer: Optional[CodeEnhancer] = None,
    knowledge_base: Optional[Any] = None,
    **config_kwargs
) -> ParallelHierarchicalDetector:
    """Factory function to create a parallel hierarchical detector.

    Args:
        llm_client: Async LLM client
        prompt_set: Optional ThreeLayerPromptSet (creates default if not provided)
        enhancer: Optional code enhancer
        knowledge_base: Optional KnowledgeBase for RAG enhancement
        **config_kwargs: Configuration parameters (including enable_rag, rag_top_k, rag_retriever_type)

    Returns:
        Configured ParallelHierarchicalDetector
    """
    from ..prompts.hierarchical_three_layer import ThreeLayerPromptFactory

    if prompt_set is None:
        prompt_set = ThreeLayerPromptFactory.create_default_prompt_set()

    hierarchical_prompts = HierarchicalPromptSet.from_three_layer_set(prompt_set)
    config = ParallelDetectorConfig(**config_kwargs)

    # Create retriever if RAG is enabled and KB is provided
    retriever = None
    if config.enable_rag and knowledge_base is not None:
        from ..rag.retriever import create_retriever
        retriever = create_retriever(
            knowledge_base,
            retriever_type=config.rag_retriever_type,
        )

    return ParallelHierarchicalDetector(
        llm_client=llm_client,
        prompt_set=hierarchical_prompts,
        config=config,
        enhancer=enhancer,
        retriever=retriever,
    )
