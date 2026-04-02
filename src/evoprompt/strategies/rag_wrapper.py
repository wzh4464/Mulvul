"""RAG wrapper that adds retrieval-augmented context to any DetectionStrategy.

Usage:
    strategy = FlatStrategy(llm_client, config)
    strategy = RAGStrategyWrapper(strategy, retriever, config)
    # predict_batch / get_ground_truth work transparently
"""

from __future__ import annotations

from typing import Any, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from evoprompt.data.dataset import Sample
    from evoprompt.rag.retriever import CodeSimilarityRetriever


class RAGStrategyWrapper:
    """Wraps any DetectionStrategy with RAG-augmented context.

    For every sample, contrastive examples (top-2 vulnerable + top-1 clean)
    are retrieved and prepended to the prompt before delegation.
    """

    def __init__(
        self,
        inner_strategy: Any,
        retriever: "CodeSimilarityRetriever",
        config: Dict[str, Any] | None = None,
    ):
        self.inner = inner_strategy
        self.retriever = retriever
        self.config = config or {}
        self.vuln_top_k: int = self.config.get("rag_vuln_top_k", 2)
        self.clean_top_k: int = self.config.get("rag_clean_top_k", 1)

    # -- public interface (same as DetectionStrategy) -----------------------

    def predict_batch(
        self, prompt: str, samples: List["Sample"], batch_idx: int
    ) -> List[str]:
        """Augment prompt with retrieved examples, then delegate."""
        augmented_prompts: List[str] = []
        for sample in samples:
            rag_context = self._retrieve_context(sample.input_text)
            if rag_context:
                augmented = f"{rag_context}\n\n{prompt}"
            else:
                augmented = prompt
            augmented_prompts.append(augmented)

        # The inner strategy's predict_batch expects a single prompt string
        # and formats it per-sample internally.  We need to call the inner
        # LLM client directly with individually augmented queries.
        return self._predict_with_augmented_prompts(
            augmented_prompts, samples, batch_idx
        )

    def get_ground_truth(self, sample: "Sample") -> str:
        return self.inner.get_ground_truth(sample)

    # -- private helpers ----------------------------------------------------

    def _retrieve_context(self, code: str) -> str:
        """Retrieve contrastive examples and return formatted context string."""
        result = self.retriever.retrieve_contrastive(
            code,
            vulnerable_top_k=self.vuln_top_k,
            clean_top_k=self.clean_top_k,
        )
        return result.formatted_text

    def _predict_with_augmented_prompts(
        self,
        augmented_prompts: List[str],
        samples: List["Sample"],
        batch_idx: int,
    ) -> List[str]:
        """Build per-sample queries with RAG context and call the LLM."""
        from evoprompt.utils.text import safe_format
        from evoprompt.data.cwe_categories import canonicalize_category

        queries = [
            safe_format(aug_prompt, input=s.input_text)
            for aug_prompt, s in zip(augmented_prompts, samples)
        ]

        print(f"      [RAG] batch predict {len(queries)} samples...")
        llm = self.inner.llm_client
        responses = llm.batch_generate(
            queries,
            temperature=0.1,
            max_tokens=20,
            batch_size=min(8, len(queries)),
            concurrent=True,
        )

        predictions: List[str] = []
        for idx, response in enumerate(responses):
            if response == "error":
                predictions.append("Other")
                continue

            cat = canonicalize_category(response)

            if cat is None:
                lower = response.lower()
                cat = canonicalize_category(lower)
                if cat is None:
                    if any(
                        p in lower
                        for p in (
                            "benign",
                            "no vuln",
                            "no security issue",
                            "not vulnerable",
                            "safe",
                            "secure code",
                        )
                    ):
                        cat = "Benign"
                    else:
                        cat = "Other"

            predictions.append(cat)

        return predictions

    # Proxy any other attribute access to inner strategy
    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)
