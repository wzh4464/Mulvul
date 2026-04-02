"""RAG-enhanced three-layer hierarchical detector.

Extends ThreeLayerDetector with retrieval-augmented generation:
- Retrieves similar examples before each layer
- Injects examples into prompts for better context
- Maintains all functionality of base detector
"""

from typing import Optional, Tuple, Dict, List
import logging

from .three_layer_detector import ThreeLayerDetector
from ..llm.client import LLMClient
from ..prompts.hierarchical_three_layer import (
    ThreeLayerPromptSet,
    MajorCategory,
    MiddleCategory,
)
from ..rag.knowledge_base import KnowledgeBase
from ..rag.retriever import CodeSimilarityRetriever, create_retriever

logger = logging.getLogger(__name__)


class RAGThreeLayerDetector(ThreeLayerDetector):
    """RAG-enhanced three-layer detector.

    Retrieves similar examples and injects them into prompts at each layer.
    """

    def __init__(
        self,
        prompt_set: ThreeLayerPromptSet,
        llm_client: LLMClient,
        knowledge_base: KnowledgeBase,
        use_scale_enhancement: bool = False,
        retriever_type: str = "lexical",
        top_k: int = 2,
        **retriever_kwargs
    ):
        """Initialize RAG-enhanced detector.

        Args:
            prompt_set: Complete prompt set for all layers
            llm_client: LLM client for detection
            knowledge_base: Knowledge base containing examples
            use_scale_enhancement: Whether to use scale enhancement
            retriever_type: Type of retriever ("lexical" or "embedding")
            top_k: Number of examples to retrieve per layer
            **retriever_kwargs: Additional arguments for retriever
        """
        super().__init__(prompt_set, llm_client, use_scale_enhancement)

        self.knowledge_base = knowledge_base
        self.top_k = top_k

        # Create retriever
        self.retriever = create_retriever(
            knowledge_base,
            retriever_type=retriever_type,
            **retriever_kwargs
        )

        logger.info(
            f"Initialized RAG detector with {retriever_type} retriever, "
            f"top_k={top_k}"
        )

    def detect(
        self,
        code: str,
        return_intermediate: bool = False
    ) -> Tuple[Optional[str], Dict]:
        """Detect vulnerability using RAG-enhanced three-layer classification.

        Args:
            code: Source code to analyze
            return_intermediate: Whether to return intermediate results

        Returns:
            Tuple of (final_cwe, details)
            details contains layer results and retrieval information
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

        # Step 2: Layer 1 - Major category with RAG
        major_category, layer1_retrieval = self._classify_layer1_with_rag(
            analysis_input
        )
        details["layer1"] = major_category.value if major_category else "Unknown"
        details["layer1_retrieval"] = layer1_retrieval

        if not major_category:
            logger.warning("Layer 1 classification failed")
            return (None, details)

        # Step 3: Layer 2 - Middle category with RAG
        middle_category, layer2_retrieval = self._classify_layer2_with_rag(
            analysis_input,
            major_category
        )
        details["layer2"] = middle_category.value if middle_category else "Unknown"
        details["layer2_retrieval"] = layer2_retrieval

        if not middle_category:
            logger.warning(f"Layer 2 classification failed for {major_category.value}")
            return (None, details)

        # Step 4: Layer 3 - Specific CWE with RAG
        cwe, layer3_retrieval = self._classify_layer3_with_rag(
            analysis_input,
            middle_category
        )
        details["layer3"] = cwe if cwe else "Unknown"
        details["layer3_retrieval"] = layer3_retrieval

        return (cwe, details)

    def _classify_layer1_with_rag(
        self,
        code: str
    ) -> Tuple[Optional[MajorCategory], Dict]:
        """Layer 1 classification with RAG enhancement.

        Args:
            code: Code to classify

        Returns:
            Tuple of (major_category, retrieval_info)
        """
        # Retrieve similar examples
        retrieval = self.retriever.retrieve_for_major_category(code, self.top_k)

        # Build enhanced prompt
        base_prompt = self.prompt_set.layer1_prompt
        if retrieval.formatted_text:
            enhanced_prompt = f"{retrieval.formatted_text}\n\n{base_prompt}"
        else:
            enhanced_prompt = base_prompt

        enhanced_prompt = enhanced_prompt.replace("{input}", code)

        # Generate
        try:
            response = self.llm_client.generate(enhanced_prompt, temperature=0.1)
            major_category = self._normalize_major_category(response)

            retrieval_info = {
                "num_examples": len(retrieval.examples),
                "similarity_scores": retrieval.similarity_scores,
                "example_categories": [ex.category for ex in retrieval.examples],
            }

            return (major_category, retrieval_info)

        except Exception as e:
            logger.error(f"Layer 1 classification failed: {e}")
            return (None, {})

    def _classify_layer2_with_rag(
        self,
        code: str,
        major_category: MajorCategory
    ) -> Tuple[Optional[MiddleCategory], Dict]:
        """Layer 2 classification with RAG enhancement.

        Args:
            code: Code to classify
            major_category: Major category from Layer 1

        Returns:
            Tuple of (middle_category, retrieval_info)
        """
        # Retrieve similar examples
        retrieval = self.retriever.retrieve_for_middle_category(
            code,
            major_category,
            self.top_k
        )

        # Build enhanced prompt
        base_prompt = self.prompt_set.get_layer2_prompt(major_category)
        if not base_prompt:
            logger.warning(f"No Layer 2 prompt for {major_category.value}")
            return (None, {})

        if retrieval.formatted_text:
            enhanced_prompt = f"{retrieval.formatted_text}\n\n{base_prompt}"
        else:
            enhanced_prompt = base_prompt

        enhanced_prompt = enhanced_prompt.replace("{input}", code)

        # Generate
        try:
            response = self.llm_client.generate(enhanced_prompt, temperature=0.1)
            middle_category = self._normalize_middle_category(response, major_category)

            retrieval_info = {
                "num_examples": len(retrieval.examples),
                "similarity_scores": retrieval.similarity_scores,
                "example_categories": [ex.category for ex in retrieval.examples],
            }

            return (middle_category, retrieval_info)

        except Exception as e:
            logger.error(f"Layer 2 classification failed: {e}")
            return (None, {})

    def _classify_layer3_with_rag(
        self,
        code: str,
        middle_category: MiddleCategory
    ) -> Tuple[Optional[str], Dict]:
        """Layer 3 classification with RAG enhancement.

        Args:
            code: Code to classify
            middle_category: Middle category from Layer 2

        Returns:
            Tuple of (cwe, retrieval_info)
        """
        # Retrieve similar examples
        retrieval = self.retriever.retrieve_for_cwe(
            code,
            middle_category,
            self.top_k
        )

        # Build enhanced prompt
        base_prompt = self.prompt_set.get_layer3_prompt(middle_category)
        if not base_prompt:
            # Fallback to first CWE
            from ..prompts.hierarchical_three_layer import MIDDLE_TO_CWE
            cwes = MIDDLE_TO_CWE.get(middle_category, [])
            if cwes:
                logger.info(
                    f"No Layer 3 prompt for {middle_category.value}, "
                    f"using first CWE: {cwes[0]}"
                )
                return (cwes[0], {})
            return (None, {})

        if retrieval.formatted_text:
            enhanced_prompt = f"{retrieval.formatted_text}\n\n{base_prompt}"
        else:
            enhanced_prompt = base_prompt

        enhanced_prompt = enhanced_prompt.replace("{input}", code)

        # Generate
        try:
            response = self.llm_client.generate(enhanced_prompt, temperature=0.1)
            cwe = self._normalize_cwe(response, middle_category)

            retrieval_info = {
                "num_examples": len(retrieval.examples),
                "similarity_scores": retrieval.similarity_scores,
                "example_cwes": [ex.cwe for ex in retrieval.examples if ex.cwe],
            }

            return (cwe, retrieval_info)

        except Exception as e:
            logger.error(f"Layer 3 classification failed: {e}")
            return (None, {})

    def get_knowledge_base_stats(self) -> Dict:
        """Get statistics about the knowledge base.

        Returns:
            Dictionary with KB statistics
        """
        return self.knowledge_base.statistics()
