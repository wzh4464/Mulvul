"""RAG (Retrieval-Augmented Generation) module for vulnerability detection.

Provides knowledge base and retrieval capabilities for enhancing prompts
with similar code examples.
"""

from .knowledge_base import (
    CodeExample,
    KnowledgeBase,
    KnowledgeBaseBuilder,
    create_knowledge_base_from_dataset,
)
from .retriever import (
    CodeSimilarityRetriever,
    EmbeddingRetriever,
    RetrievalResult,
    create_retriever,
)

__all__ = [
    "CodeExample",
    "KnowledgeBase",
    "KnowledgeBaseBuilder",
    "create_knowledge_base_from_dataset",
    "CodeSimilarityRetriever",
    "EmbeddingRetriever",
    "RetrievalResult",
    "create_retriever",
]
