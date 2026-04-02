"""RAG retriever for code vulnerability examples.

Retrieves similar code examples from knowledge base and formats them for prompt enhancement.
"""

from typing import List, Optional, Tuple
import re
from dataclasses import dataclass

from .knowledge_base import KnowledgeBase, CodeExample
from ..prompts.hierarchical_three_layer import MajorCategory, MiddleCategory


@dataclass
class RetrievalResult:
    """Result of example retrieval.

    Attributes:
        examples: Retrieved code examples
        formatted_text: Formatted text ready for prompt injection
        similarity_scores: Similarity scores for each example
        debug_info: Debug information about retrieval
    """
    examples: List[CodeExample]
    formatted_text: str
    similarity_scores: List[float]
    debug_info: Optional[dict] = None


class CodeSimilarityRetriever:
    """Retrieves similar code examples using simple text similarity.

    For production use, consider using embeddings (e.g., CodeBERT, OpenAI embeddings).
    This implementation uses fast lexical similarity for efficiency.

    Supports contrastive retrieval (SCALE-style) by retrieving both vulnerable
    and clean examples for comparison.
    """

    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        contrastive: bool = False,
        clean_pool_frac: float = 1.0,
        clean_pool_seed: int = 42,
        debug: bool = False
    ):
        """Initialize retriever.

        Args:
            knowledge_base: Knowledge base containing examples
            contrastive: Enable contrastive retrieval mode
            clean_pool_frac: Fraction of clean pool to subsample (0.0 to 1.0)
            clean_pool_seed: Random seed for clean pool subsampling
            debug: Enable debug output
        """
        self.kb = knowledge_base
        self.contrastive = contrastive
        self.clean_pool_frac = clean_pool_frac
        self.clean_pool_seed = clean_pool_seed
        self.debug = debug
        self._subsampled_clean_pool: Optional[List[CodeExample]] = None

    def retrieve_for_major_category(
        self,
        query_code: str,
        top_k: int = 2
    ) -> RetrievalResult:
        """Retrieve similar examples across all major categories.

        Args:
            query_code: Code to find similar examples for
            top_k: Number of examples to retrieve

        Returns:
            Retrieval result with examples and formatted text
        """
        all_examples = []

        # Gather examples from all major categories
        for examples in self.kb.major_examples.values():
            all_examples.extend(examples)

        return self._retrieve_from_pool(query_code, all_examples, top_k)

    def retrieve_for_middle_category(
        self,
        query_code: str,
        major_category: MajorCategory,
        top_k: int = 2
    ) -> RetrievalResult:
        """Retrieve similar examples for a specific major category.

        Args:
            query_code: Code to find similar examples for
            major_category: Major category to search within
            top_k: Number of examples to retrieve

        Returns:
            Retrieval result with examples and formatted text
        """
        # Get examples for this major category from middle categories
        all_examples = []
        for examples in self.kb.middle_examples.values():
            # Filter to examples matching this major category
            for ex in examples:
                if ex.category in [mc.value for mc in major_category.__class__]:
                    continue
                all_examples.append(ex)

        # Fallback: use major category examples if not enough middle examples
        if len(all_examples) < top_k:
            major_examples = self.kb.major_examples.get(major_category.value, [])
            all_examples.extend(major_examples)

        return self._retrieve_from_pool(query_code, all_examples, top_k)

    def retrieve_for_middle_category_by_name(
        self,
        query_code: str,
        major_name: str,
        top_k: int = 2
    ) -> RetrievalResult:
        """String-accepting wrapper for retrieve_for_middle_category.

        Args:
            query_code: Code to find similar examples for
            major_name: Major category name (e.g. "Memory", "Injection")
            top_k: Number of examples to retrieve

        Returns:
            Retrieval result with examples and formatted text
        """
        try:
            major_category = MajorCategory(major_name)
        except ValueError:
            # Try case-insensitive match
            for mc in MajorCategory:
                if mc.value.lower() == major_name.lower():
                    major_category = mc
                    break
            else:
                return RetrievalResult(
                    examples=[], formatted_text="", similarity_scores=[],
                    debug_info={"pool_size": 0, "message": f"Unknown major category: {major_name}"}
                )
        return self.retrieve_for_middle_category(query_code, major_category, top_k)

    def retrieve_for_cwe(
        self,
        query_code: str,
        middle_category: MiddleCategory,
        top_k: int = 2
    ) -> RetrievalResult:
        """Retrieve similar examples for a specific middle category.

        Args:
            query_code: Code to find similar examples for
            middle_category: Middle category to search within
            top_k: Number of examples to retrieve

        Returns:
            Retrieval result with examples and formatted text
        """
        # Get CWE examples for this middle category
        from ..prompts.hierarchical_three_layer import MIDDLE_TO_CWE

        all_examples = []
        cwes = MIDDLE_TO_CWE.get(middle_category, [])

        for cwe in cwes:
            examples = self.kb.cwe_examples.get(cwe, [])
            all_examples.extend(examples)

        # Fallback: use middle category examples
        if len(all_examples) < top_k:
            middle_examples = self.kb.middle_examples.get(middle_category.value, [])
            all_examples.extend(middle_examples)

        return self._retrieve_from_pool(query_code, all_examples, top_k)

    def retrieve_for_cwe_by_name(
        self,
        query_code: str,
        middle_name: str,
        top_k: int = 2
    ) -> RetrievalResult:
        """String-accepting wrapper for retrieve_for_cwe.

        Args:
            query_code: Code to find similar examples for
            middle_name: Middle category name (e.g. "Buffer Overflow", "SQL Injection")
            top_k: Number of examples to retrieve

        Returns:
            Retrieval result with examples and formatted text
        """
        try:
            middle_category = MiddleCategory(middle_name)
        except ValueError:
            # Try case-insensitive match
            for mc in MiddleCategory:
                if mc.value.lower() == middle_name.lower():
                    middle_category = mc
                    break
            else:
                return RetrievalResult(
                    examples=[], formatted_text="", similarity_scores=[],
                    debug_info={"pool_size": 0, "message": f"Unknown middle category: {middle_name}"}
                )
        return self.retrieve_for_cwe(query_code, middle_category, top_k)

    def _retrieve_from_pool(
        self,
        query_code: str,
        example_pool: List[CodeExample],
        top_k: int
    ) -> RetrievalResult:
        """Retrieve top-k similar examples from pool.

        Args:
            query_code: Code to compare against
            example_pool: Pool of examples to search
            top_k: Number to retrieve

        Returns:
            Retrieval result
        """
        if not example_pool:
            return RetrievalResult(
                examples=[],
                formatted_text="",
                similarity_scores=[],
                debug_info={"pool_size": 0, "message": "Empty example pool"}
            )

        # Compute similarities
        scored_examples = []
        for example in example_pool:
            similarity = self._compute_similarity(query_code, example.code)
            scored_examples.append((similarity, example))

        # Sort by similarity (descending)
        scored_examples.sort(key=lambda x: x[0], reverse=True)

        # Take top-k
        top_examples = scored_examples[:top_k]

        # Format for prompt
        formatted = self._format_examples([ex for _, ex in top_examples])

        # Build debug info
        debug_info = None
        if self.debug:
            debug_info = {
                "pool_size": len(example_pool),
                "top_k": top_k,
                "retrieved": [
                    {
                        "category": ex.category,
                        "cwe": ex.cwe,
                        "similarity": round(score, 4),
                        "code_preview": ex.code[:100] + "..." if len(ex.code) > 100 else ex.code
                    }
                    for score, ex in top_examples
                ],
                "query_preview": query_code[:100] + "..." if len(query_code) > 100 else query_code
            }
            self._print_debug(debug_info)

        return RetrievalResult(
            examples=[ex for _, ex in top_examples],
            formatted_text=formatted,
            similarity_scores=[score for score, _ in top_examples],
            debug_info=debug_info
        )

    def _get_clean_pool(self) -> List[CodeExample]:
        """Get (possibly subsampled) clean pool.

        Returns:
            List of clean examples, subsampled if clean_pool_frac < 1.0
        """
        if self._subsampled_clean_pool is not None:
            return self._subsampled_clean_pool

        if not self.kb.clean_examples or self.clean_pool_frac >= 1.0:
            self._subsampled_clean_pool = self.kb.clean_examples
        else:
            import random
            rng = random.Random(self.clean_pool_seed)
            n_samples = int(len(self.kb.clean_examples) * self.clean_pool_frac)
            self._subsampled_clean_pool = rng.sample(self.kb.clean_examples, n_samples)

        return self._subsampled_clean_pool

    def retrieve_contrastive(
        self,
        query_code: str,
        vulnerable_top_k: int = 2,
        clean_top_k: int = 1
    ) -> RetrievalResult:
        """Retrieve both vulnerable AND clean examples for contrastive learning.

        This implements SCALE-style retrieval where both positive (vulnerable)
        and negative (clean) examples are retrieved to help the model understand
        the contrast between vulnerable and safe code patterns.

        Args:
            query_code: Code to find similar examples for
            vulnerable_top_k: Number of vulnerable examples to retrieve
            clean_top_k: Number of clean examples to retrieve

        Returns:
            Retrieval result with both vulnerable and clean examples
        """
        # Get vulnerable examples
        vuln_result = self.retrieve_for_major_category(query_code, vulnerable_top_k)

        # Get clean examples
        clean_pool = self._get_clean_pool()
        clean_result = self._retrieve_from_pool(query_code, clean_pool, clean_top_k)

        # Combine examples and scores
        all_examples = vuln_result.examples + clean_result.examples
        all_scores = vuln_result.similarity_scores + clean_result.similarity_scores

        # Format with contrastive IDs
        formatted = self._format_contrastive_examples(
            vuln_result.examples, clean_result.examples
        )

        debug_info = {
            "vulnerable_count": len(vuln_result.examples),
            "clean_count": len(clean_result.examples),
            "clean_pool_size": len(clean_pool),
            "clean_pool_frac": self.clean_pool_frac,
            "vulnerable_top_similarity": vuln_result.debug_info.get("top_similarity", 0.0) if vuln_result.debug_info else 0.0,
            "clean_top_similarity": clean_result.debug_info.get("top_similarity", 0.0) if clean_result.debug_info else 0.0,
        }

        return RetrievalResult(
            examples=all_examples,
            formatted_text=formatted,
            similarity_scores=all_scores,
            debug_info=debug_info
        )

    def _format_contrastive_examples(
        self,
        vulnerable: List[CodeExample],
        clean: List[CodeExample]
    ) -> str:
        """Format examples with IDs for contrastive retrieval.

        Args:
            vulnerable: List of vulnerable examples
            clean: List of clean examples

        Returns:
            Formatted string with [VUL-n] and [CLEAN-n] prefixes
        """
        parts = ["Retrieved vulnerability knowledge:\n"]

        # Vulnerable examples
        for i, ex in enumerate(vulnerable, 1):
            parts.append(f"[VUL-{i}] Category: {ex.category}")
            if ex.cwe:
                parts.append(f" | CWE: {ex.cwe}")
            parts.append(f"\nCode: {ex.code}\nDescription: {ex.description}\n")

        # Clean examples
        for i, ex in enumerate(clean, 1):
            parts.append(f"[CLEAN-{i}] Category: {ex.category}")
            parts.append(f"\nCode: {ex.code}\nDescription: {ex.description}\n")

        return "\n".join(parts)

    def _print_debug(self, debug_info: dict) -> None:
        """Print debug information about retrieval."""
        print("\n" + "=" * 60)
        print("RAG Retrieval Debug Info")
        print("=" * 60)
        print(f"Pool size: {debug_info['pool_size']}")
        print(f"Top-k: {debug_info['top_k']}")
        print(f"\nQuery preview: {debug_info['query_preview']}")
        print("\nRetrieved examples:")
        for i, ex in enumerate(debug_info['retrieved'], 1):
            print(f"\n  [{i}] Category: {ex['category']}, CWE: {ex['cwe']}")
            print(f"      Similarity: {ex['similarity']}")
            print(f"      Code: {ex['code_preview']}")
        print("=" * 60 + "\n")

    def _compute_similarity(self, code1: str, code2: str) -> float:
        """Compute simple lexical similarity between two code snippets.

        Uses Jaccard similarity on token sets for efficiency.
        For production, consider using embeddings.

        Args:
            code1: First code snippet
            code2: Second code snippet

        Returns:
            Similarity score in [0, 1]
        """
        # Tokenize (simple approach)
        tokens1 = set(self._tokenize(code1))
        tokens2 = set(self._tokenize(code2))

        if not tokens1 or not tokens2:
            return 0.0

        # Jaccard similarity
        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)

        return intersection / union if union > 0 else 0.0

    def _tokenize(self, code: str) -> List[str]:
        """Simple tokenization of code.

        Args:
            code: Source code

        Returns:
            List of tokens
        """
        # Remove comments (simple approach)
        code = re.sub(r'//.*', '', code)
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)

        # Split on non-alphanumeric characters
        tokens = re.findall(r'\w+', code.lower())

        return tokens

    def _format_examples(self, examples: List[CodeExample]) -> str:
        """Format examples for prompt injection.

        Args:
            examples: Code examples to format

        Returns:
            Formatted string for prompt
        """
        if not examples:
            return ""

        formatted_parts = ["Here are similar examples for reference:\n"]

        for i, example in enumerate(examples, 1):
            formatted_parts.append(f"Example {i}:")
            formatted_parts.append(f"Category: {example.category}")
            if example.cwe:
                formatted_parts.append(f"CWE: {example.cwe}")
            formatted_parts.append(f"Description: {example.description}")
            formatted_parts.append(f"Code:\n{example.code}")
            formatted_parts.append("")  # Empty line

        return "\n".join(formatted_parts)


class EmbeddingRetriever(CodeSimilarityRetriever):
    """Retriever using embeddings for semantic similarity.

    This is a placeholder for future implementation using:
    - OpenAI embeddings
    - CodeBERT
    - Other code embedding models

    For now, falls back to lexical similarity.
    """

    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        embedding_model: Optional[str] = None,
        contrastive: bool = False,
        clean_pool_frac: float = 1.0,
        clean_pool_seed: int = 42,
        debug: bool = False
    ):
        """Initialize embedding retriever.

        Args:
            knowledge_base: Knowledge base
            embedding_model: Name of embedding model (not yet implemented)
            contrastive: Enable contrastive retrieval mode
            clean_pool_frac: Fraction of clean pool to subsample (0.0 to 1.0)
            clean_pool_seed: Random seed for clean pool subsampling
            debug: Enable debug output
        """
        super().__init__(
            knowledge_base,
            contrastive=contrastive,
            clean_pool_frac=clean_pool_frac,
            clean_pool_seed=clean_pool_seed,
            debug=debug
        )
        self.embedding_model = embedding_model

        if embedding_model:
            import warnings
            warnings.warn(
                f"Embedding model '{embedding_model}' not yet implemented. "
                "Falling back to lexical similarity."
            )

    def _compute_similarity(self, code1: str, code2: str) -> float:
        """Compute similarity using embeddings (not yet implemented).

        Falls back to lexical similarity.
        """
        # TODO: Implement embedding-based similarity
        # For now, use parent's lexical similarity
        return super()._compute_similarity(code1, code2)


def create_retriever(
    knowledge_base: KnowledgeBase,
    retriever_type: str = "lexical",
    **kwargs
) -> CodeSimilarityRetriever:
    """Factory function to create retriever.

    Args:
        knowledge_base: Knowledge base to use
        retriever_type: Type of retriever ("lexical" or "embedding")
        **kwargs: Additional arguments for retriever (contrastive, clean_pool_frac, etc.)

    Returns:
        Configured retriever
    """
    if retriever_type == "lexical":
        return CodeSimilarityRetriever(knowledge_base, **kwargs)
    elif retriever_type == "embedding":
        return EmbeddingRetriever(knowledge_base, **kwargs)
    else:
        raise ValueError(f"Unknown retriever type: {retriever_type}")


class MulVulRetriever:
    """Retriever for MulVul multi-agent system.

    Supports hierarchical knowledge base with three levels:
    - by_major: Memory, Injection, Logic, Input, Crypto
    - by_middle: Buffer Errors, Memory Management, etc.
    - by_cwe: CWE-119, CWE-416, etc.
    """

    MAJOR_CATEGORIES = ["Memory", "Injection", "Logic", "Input", "Crypto"]

    def __init__(self, knowledge_base_path: str = None, knowledge_base: KnowledgeBase = None):
        """Initialize retriever.

        Args:
            knowledge_base_path: Path to JSON knowledge base file
            knowledge_base: Legacy KnowledgeBase object
        """
        self.by_major = {}
        self.by_middle = {}
        self.by_cwe = {}

        if knowledge_base_path:
            self._load_from_json(knowledge_base_path)
        elif knowledge_base:
            self._load_from_kb(knowledge_base)

    def _load_from_json(self, path: str):
        """Load from hierarchical JSON knowledge base file."""
        import json
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Support both flat and hierarchical formats
        if "by_major" in data:
            self.by_major = data.get("by_major", {})
            self.by_middle = data.get("by_middle", {})
            self.by_cwe = data.get("by_cwe", {})
        else:
            # Flat format (legacy)
            self.by_major = data

        total = sum(len(v) for v in self.by_major.values())
        total += sum(len(v) for v in self.by_middle.values())
        total += sum(len(v) for v in self.by_cwe.values())
        print(f"📚 Loaded knowledge base: {total} samples")

    def _load_from_kb(self, kb: KnowledgeBase):
        """Load from legacy KnowledgeBase object."""
        for cat, examples in kb.major_examples.items():
            self.by_major[cat] = [
                {"code": ex.code, "major": cat, "cwe": ex.cwe, "description": ex.description}
                for ex in examples
            ]

    def retrieve_contrastive(self, query_code: str, n_per_category: int = 2) -> List[dict]:
        """Retrieve cross-type contrastive evidence for Router Agent."""
        results = []
        for category in self.MAJOR_CATEGORIES:
            samples = self.retrieve_from_category(query_code, category, top_k=n_per_category)
            results.extend(samples)
        return results

    def retrieve_from_category(self, query_code: str, category: str, top_k: int = 3) -> List[dict]:
        """Retrieve examples from a specific major category."""
        samples = self.by_major.get(category, [])
        if not samples:
            return []
        return self._rank_and_return(query_code, samples, category, top_k)

    def retrieve_from_middle(self, query_code: str, middle: str, top_k: int = 3) -> List[dict]:
        """Retrieve examples from a specific middle category."""
        samples = self.by_middle.get(middle, [])
        if not samples:
            return []
        return self._rank_and_return(query_code, samples, middle, top_k)

    def retrieve_from_cwe(self, query_code: str, cwe: str, top_k: int = 3) -> List[dict]:
        """Retrieve examples from a specific CWE."""
        samples = self.by_cwe.get(cwe, [])
        if not samples:
            return []
        return self._rank_and_return(query_code, samples, cwe, top_k)

    def _rank_and_return(self, query_code: str, samples: List[dict], category: str, top_k: int) -> List[dict]:
        """Rank samples by similarity and return top-k."""
        scored = []
        for sample in samples:
            similarity = self._compute_similarity(query_code, sample.get("code", ""))
            scored.append((similarity, sample))

        scored.sort(key=lambda x: x[0], reverse=True)

        return [
            {
                "code": s["code"],
                "category": category,
                "cwe": s.get("cwe", ""),
                "middle": s.get("middle", ""),
                "major": s.get("major", ""),
                "description": s.get("description", ""),
                "similarity": round(score, 4),
            }
            for score, s in scored[:top_k]
        ]

    def _compute_similarity(self, code1: str, code2: str) -> float:
        """Compute Jaccard similarity on token sets."""
        tokens1 = set(re.findall(r'\w+', code1.lower()))
        tokens2 = set(re.findall(r'\w+', code2.lower()))

        if not tokens1 or not tokens2:
            return 0.0

        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)
        return intersection / union if union > 0 else 0.0
