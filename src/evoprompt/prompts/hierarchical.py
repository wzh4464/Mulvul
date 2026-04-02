"""Hierarchical prompt structure for vulnerability detection.

This module implements a hierarchical prompt system with:
- Major category routing (e.g., Memory, Injection, Logic)
- Minor category detection (specific CWE types)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum


class CWECategory(Enum):
    """CWE vulnerability major categories."""
    MEMORY = "Memory"  # Buffer overflow, use-after-free, etc.
    INJECTION = "Injection"  # SQL injection, XSS, Command injection
    LOGIC = "Logic"  # Authentication, race conditions
    CRYPTO = "Crypto"  # Cryptographic weaknesses
    INPUT = "Input"  # Input validation issues
    BENIGN = "Benign"  # No vulnerability


# CWE映射到大类
CWE_TO_MAJOR_CATEGORY = {
    "CWE-120": CWECategory.MEMORY,  # Buffer overflow
    "CWE-787": CWECategory.MEMORY,  # Out-of-bounds write
    "CWE-125": CWECategory.MEMORY,  # Out-of-bounds read
    "CWE-416": CWECategory.MEMORY,  # Use after free
    "CWE-476": CWECategory.MEMORY,  # NULL pointer dereference
    "CWE-190": CWECategory.MEMORY,  # Integer overflow
    "CWE-79": CWECategory.INJECTION,  # XSS
    "CWE-89": CWECategory.INJECTION,  # SQL injection
    "CWE-78": CWECategory.INJECTION,  # OS command injection
    "CWE-22": CWECategory.INPUT,  # Path traversal
    "CWE-20": CWECategory.INPUT,  # Improper input validation
}


@dataclass
class HierarchicalPrompt:
    """Hierarchical prompt with routing and detection components.

    Attributes:
        router_prompt: Prompt for routing to major category
        category_prompts: Dict mapping major categories to detection prompts
        metadata: Additional metadata
    """
    router_prompt: str
    category_prompts: Dict[CWECategory, str] = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)

    def get_detection_prompt(self, category: CWECategory) -> Optional[str]:
        """Get detection prompt for a specific category."""
        return self.category_prompts.get(category)

    def set_detection_prompt(self, category: CWECategory, prompt: str):
        """Set detection prompt for a specific category."""
        self.category_prompts[category] = prompt

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "router_prompt": self.router_prompt,
            "category_prompts": {
                cat.value: prompt for cat, prompt in self.category_prompts.items()
            },
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "HierarchicalPrompt":
        """Create from dictionary."""
        return cls(
            router_prompt=data["router_prompt"],
            category_prompts={
                CWECategory(cat): prompt
                for cat, prompt in data.get("category_prompts", {}).items()
            },
            metadata=data.get("metadata", {}),
        )


class PromptHierarchy:
    """Manages the hierarchical prompt system for vulnerability detection."""

    def __init__(self):
        self.router_prompt: Optional[str] = None
        self.category_prompts: Dict[CWECategory, str] = {}

    def set_router_prompt(self, prompt: str):
        """Set the router prompt for major category classification."""
        self.router_prompt = prompt

    def set_category_prompt(self, category: CWECategory, prompt: str):
        """Set detection prompt for a specific category."""
        self.category_prompts[category] = prompt

    def get_category_prompt(self, category: CWECategory) -> Optional[str]:
        """Get detection prompt for a specific category."""
        return self.category_prompts.get(category)

    def create_default_router_prompt(self) -> str:
        """Create default router prompt for major category classification."""
        return """You are a security expert analyzing code for vulnerabilities.

First, classify this code into one of these major vulnerability categories:
- Memory: Buffer overflow, use-after-free, null pointer, memory corruption
- Injection: SQL injection, XSS, command injection
- Logic: Authentication bypass, race conditions, logic errors
- Input: Input validation, path traversal
- Benign: No significant security issues

Code to analyze:
{input}

Classification (respond with ONLY the category name):"""

    def create_default_category_prompts(self) -> Dict[CWECategory, str]:
        """Create default detection prompts for each category."""
        return {
            CWECategory.MEMORY: """Analyze this code for MEMORY vulnerabilities:
- Buffer overflow (CWE-120, CWE-787)
- Out-of-bounds access (CWE-125)
- Use-after-free (CWE-416)
- NULL pointer dereference (CWE-476)
- Integer overflow (CWE-190)

Code:
{input}

Respond 'vulnerable' if you find memory safety issues, 'benign' if safe:""",

            CWECategory.INJECTION: """Analyze this code for INJECTION vulnerabilities:
- SQL injection (CWE-89)
- Cross-site scripting (CWE-79)
- OS command injection (CWE-78)

Code:
{input}

Respond 'vulnerable' if you find injection vulnerabilities, 'benign' if safe:""",

            CWECategory.LOGIC: """Analyze this code for LOGIC vulnerabilities:
- Authentication bypass
- Race conditions
- Logic errors in security checks

Code:
{input}

Respond 'vulnerable' if you find logic vulnerabilities, 'benign' if safe:""",

            CWECategory.INPUT: """Analyze this code for INPUT validation vulnerabilities:
- Path traversal (CWE-22)
- Improper input validation (CWE-20)
- Uncontrolled resource consumption

Code:
{input}

Respond 'vulnerable' if you find input validation issues, 'benign' if safe:""",

            CWECategory.BENIGN: """Verify that this code is safe:

Code:
{input}

Respond 'benign' if safe, 'vulnerable' if you find any issues:""",
        }

    def initialize_with_defaults(self):
        """Initialize with default prompts."""
        self.router_prompt = self.create_default_router_prompt()
        self.category_prompts = self.create_default_category_prompts()

    def to_hierarchical_prompt(self) -> HierarchicalPrompt:
        """Convert to HierarchicalPrompt object."""
        return HierarchicalPrompt(
            router_prompt=self.router_prompt or self.create_default_router_prompt(),
            category_prompts=self.category_prompts.copy(),
        )


def get_cwe_major_category(cwe: str) -> CWECategory:
    """Get major category for a CWE identifier.

    Args:
        cwe: CWE identifier (e.g., "CWE-120")

    Returns:
        Major category enum value, defaults to BENIGN if unknown
    """
    return CWE_TO_MAJOR_CATEGORY.get(cwe, CWECategory.BENIGN)
