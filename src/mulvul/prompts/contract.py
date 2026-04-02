"""Prompt contract validation for ensuring prompt quality.

Validates that prompts contain required placeholders, output constraints,
and trainable section boundaries.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# Supported placeholder variants (all normalized to {input})
_PLACEHOLDER_PATTERNS = [
    r"\{input\}",
    r"\{CODE\}",
    r"\{\{CODE\}\}",
]

# Output constraint keywords
_OUTPUT_CONSTRAINT_KEYWORDS = [
    "respond with",
    "respond:",
    "output:",
    "format:",
    "confidence:",
    "answer with",
    "reply with",
    "classify as",
]

# Trainable boundary marker pairs
_TRAINABLE_MARKER_PAIRS: List[Tuple[str, str]] = [
    ("### ANALYSIS GUIDANCE START", "### ANALYSIS GUIDANCE END"),
    ("{{TRAINABLE_START}}", "{{TRAINABLE_END}}"),
]


@dataclass
class PromptContract:
    """Defines the contract a prompt must satisfy.

    Attributes:
        required_placeholders: Placeholders that must be present
            (default: ["{input}"])
        trainable_marker_pairs: Pairs of (start, end) markers for
            trainable sections
        output_constraint_keywords: Keywords indicating output format
            specification
    """

    required_placeholders: List[str] = field(
        default_factory=lambda: ["{input}"]
    )
    trainable_marker_pairs: List[Tuple[str, str]] = field(
        default_factory=lambda: list(_TRAINABLE_MARKER_PAIRS)
    )
    output_constraint_keywords: List[str] = field(
        default_factory=lambda: list(_OUTPUT_CONSTRAINT_KEYWORDS)
    )


@dataclass
class ValidationResult:
    """Result of prompt validation.

    Attributes:
        is_valid: Whether the prompt passes all required checks
        errors: List of validation errors (required checks that failed)
        warnings: List of validation warnings (recommended checks
            that failed)
        has_placeholder: Whether any recognized placeholder was found
        has_output_constraint: Whether output format constraint was
            detected
        has_trainable_boundaries: Whether trainable section markers
            were found
    """

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    has_placeholder: bool = False
    has_output_constraint: bool = False
    has_trainable_boundaries: bool = False


class PromptContractValidator:
    """Validates prompts against a PromptContract.

    Can be used as a class with custom contracts, or via direct calls
    with the default contract.

    Usage::

        # Class-level call with default contract
        result = PromptContractValidator.validate(prompt)

        # Instance call with custom contract
        contract = PromptContract(required_placeholders=["{input}", "{ctx}"])
        validator = PromptContractValidator(contract)
        result = validator.validate(prompt)
    """

    def __init__(self, contract: Optional[PromptContract] = None) -> None:
        self.contract = contract or PromptContract()

    @staticmethod
    def _has_any_placeholder(prompt: str) -> bool:
        """Check if prompt contains any recognized placeholder."""
        for pattern in _PLACEHOLDER_PATTERNS:
            if re.search(pattern, prompt):
                return True
        return False

    @staticmethod
    def _has_output_constraint(
        prompt: str, keywords: List[str]
    ) -> bool:
        """Check if prompt contains output format constraints."""
        prompt_lower = prompt.lower()
        return any(kw in prompt_lower for kw in keywords)

    @staticmethod
    def _has_trainable_boundaries(
        prompt: str, marker_pairs: List[Tuple[str, str]]
    ) -> bool:
        """Check if prompt has matching trainable section markers."""
        for start, end in marker_pairs:
            if start in prompt and end in prompt:
                return True
        return False

    @staticmethod
    def extract_trainable_sections(prompt: str) -> List[str]:
        """Extract content between trainable markers.

        Args:
            prompt: The prompt text to extract sections from.

        Returns:
            List of extracted trainable section contents.
        """
        sections: List[str] = []
        for start, end in _TRAINABLE_MARKER_PAIRS:
            pattern = (
                re.escape(start) + r"\n?(.*?)\n?" + re.escape(end)
            )
            matches = re.findall(pattern, prompt, re.DOTALL)
            sections.extend(m.strip() for m in matches if m.strip())
        return sections

    @staticmethod
    def _do_validate(
        prompt: str, contract: PromptContract
    ) -> ValidationResult:
        """Core validation logic.

        Args:
            prompt: The prompt text to validate.
            contract: The contract to validate against.

        Returns:
            ValidationResult with validation outcome.
        """
        errors: List[str] = []
        warnings: List[str] = []

        # Check placeholders
        has_placeholder = False
        if contract.required_placeholders == ["{input}"]:
            # Default contract: accept any recognized placeholder variant
            has_placeholder = PromptContractValidator._has_any_placeholder(
                prompt
            )
        else:
            # Custom contract: check all required placeholders
            has_placeholder = all(
                p in prompt for p in contract.required_placeholders
            )

        if not has_placeholder:
            placeholders_str = ", ".join(contract.required_placeholders)
            errors.append(
                f"Missing required placeholder. "
                f"Expected one of: {placeholders_str} "
                f"(or {{CODE}}/{{{{CODE}}}})"
            )

        # Check output constraint
        has_output_constraint = (
            PromptContractValidator._has_output_constraint(
                prompt, contract.output_constraint_keywords
            )
        )
        if not has_output_constraint:
            warnings.append(
                "No output format constraint detected. "
                "Consider adding response format instructions."
            )

        # Check trainable boundaries
        has_trainable = (
            PromptContractValidator._has_trainable_boundaries(
                prompt, contract.trainable_marker_pairs
            )
        )

        is_valid = len(errors) == 0

        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            has_placeholder=has_placeholder,
            has_output_constraint=has_output_constraint,
            has_trainable_boundaries=has_trainable,
        )

    def validate(
        self_or_prompt: "PromptContractValidator | str",
        prompt_or_none: Optional[str] = None,
        *,
        contract: Optional[PromptContract] = None,
    ) -> ValidationResult:
        """Validate a prompt against the contract.

        Works both as a class-level call and an instance method call:

        - ``PromptContractValidator.validate(prompt)`` -- uses
          default contract
        - ``validator.validate(prompt)`` -- uses instance contract

        Args:
            self_or_prompt: Either a PromptContractValidator instance
                (when called on instance) or the prompt string (when
                called on the class directly).
            prompt_or_none: The prompt string when called on an instance.
            contract: Optional contract override.

        Returns:
            ValidationResult with validation outcome.
        """
        if isinstance(self_or_prompt, str):
            # Called as PromptContractValidator.validate(prompt_string)
            prompt = self_or_prompt
            c = contract or PromptContract()
        else:
            # Called as instance.validate(prompt_string)
            prompt = prompt_or_none  # type: ignore[assignment]
            c = contract or self_or_prompt.contract
        return PromptContractValidator._do_validate(prompt, c)
