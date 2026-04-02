"""Base classes and data structures for MulVul agents."""

from dataclasses import dataclass, field
from typing import Optional, List

BENIGN_CATEGORY = "Benign"
UNKNOWN_CATEGORY = "Unknown"


@dataclass
class DetectionResult:
    """Structured detection result with confidence and evidence.

    Implements the (y_m, c_m, e_m) tuple from method.md:
    - prediction: vulnerability type or "Benign"
    - confidence: 0.0-1.0 confidence score
    - evidence: supporting evidence from code
    """

    prediction: str
    confidence: float = 0.5
    evidence: str = ""

    # Hierarchical classification details
    category: str = ""  # Major category (Memory/Injection/Logic/Input/Crypto)
    subcategory: str = ""  # Middle category
    cwe: str = ""  # Specific CWE

    # Metadata
    agent_id: str = ""
    raw_response: str = ""

    def is_vulnerable(self) -> bool:
        """Check if prediction indicates vulnerability."""
        return self.prediction.lower() not in (
            BENIGN_CATEGORY.lower(),
            "safe",
            "non-vul",
            "non-vulnerable",
        )

    def to_dict(self) -> dict:
        return {
            "prediction": self.prediction,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "category": self.category,
            "subcategory": self.subcategory,
            "cwe": self.cwe,
            "agent_id": self.agent_id,
        }


@dataclass
class RoutingResult:
    """Result from Router Agent with ranked categories."""

    categories: List[tuple]  # [(category, confidence), ...]
    evidence_used: List[dict] = field(default_factory=list)
    raw_response: str = ""

    @property
    def top_category(self) -> str:
        return self.categories[0][0] if self.categories else UNKNOWN_CATEGORY

    @property
    def top_confidence(self) -> float:
        return self.categories[0][1] if self.categories else 0.0

    def get_top_k(self, k: Optional[int] = None) -> List[tuple]:
        if k is None:
            return list(self.categories)
        return self.categories[:k]
