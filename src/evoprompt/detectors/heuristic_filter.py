"""Heuristic filters for vulnerability detection validation.

Rule-based checks to validate or adjust LLM predictions.
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class HeuristicResult:
    """Result of heuristic validation."""
    is_valid: bool
    confidence_adjustment: float  # -1.0 to 1.0
    reason: str


class VulnerabilityHeuristicFilter:
    """Rule-based heuristic filter for vulnerability detection."""

    # Memory-related patterns
    MEMORY_PATTERNS = {
        "malloc_free": re.compile(r'\b(malloc|free|realloc|calloc|new|delete)\b'),
        "pointer_ops": re.compile(r'(\*\s*\w+|\w+\s*->|\w+\s*\[\s*\w+\s*\])'),
        "null_check": re.compile(r'\b(NULL|nullptr|null)\b', re.IGNORECASE),
        "buffer_funcs": re.compile(r'\b(strcpy|strncpy|memcpy|memmove|sprintf|gets|strcat)\b'),
        "array_access": re.compile(r'\w+\s*\[\s*[^\]]+\s*\]'),
    }

    # Injection-related patterns
    INJECTION_PATTERNS = {
        "sql": re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION)\b', re.IGNORECASE),
        "command": re.compile(r'\b(system|exec|popen|shell_exec|eval|subprocess)\b'),
        "xss": re.compile(r'\b(innerHTML|document\.write|\.html\(|<script)\b'),
    }

    # Logic-related patterns
    LOGIC_PATTERNS = {
        "auth": re.compile(r'\b(auth|login|password|session|token|credential|permission)\b', re.IGNORECASE),
        "access_control": re.compile(r'\b(admin|role|privilege|access|allow|deny)\b', re.IGNORECASE),
    }

    # Crypto-related patterns
    CRYPTO_PATTERNS = {
        "weak_algo": re.compile(r'\b(MD5|SHA1|DES|RC4|ECB)\b', re.IGNORECASE),
        "crypto_funcs": re.compile(r'\b(encrypt|decrypt|hash|cipher|AES|RSA)\b', re.IGNORECASE),
        "random": re.compile(r'\b(rand|random|srand|mt_rand)\b'),
    }

    # Input-related patterns
    INPUT_PATTERNS = {
        "path": re.compile(r'(\.\./|\.\.\\|path|file|directory)', re.IGNORECASE),
        "format": re.compile(r'%[sdxnp]'),
    }

    def validate_memory(self, code: str, middle_category: str) -> HeuristicResult:
        """Validate Memory category predictions."""
        has_malloc = bool(self.MEMORY_PATTERNS["malloc_free"].search(code))
        has_pointer = bool(self.MEMORY_PATTERNS["pointer_ops"].search(code))
        has_null = bool(self.MEMORY_PATTERNS["null_check"].search(code))
        has_buffer = bool(self.MEMORY_PATTERNS["buffer_funcs"].search(code))
        has_array = bool(self.MEMORY_PATTERNS["array_access"].search(code))

        middle_lower = middle_category.lower()

        # Use After Free validation
        if "use after free" in middle_lower or "use-after-free" in middle_lower:
            if not has_malloc:
                return HeuristicResult(False, -0.5, "Use After Free requires free/delete operations")

        # Buffer Overflow validation
        if "buffer" in middle_lower or "overflow" in middle_lower:
            if not (has_buffer or has_array):
                return HeuristicResult(False, -0.3, "Buffer Overflow should have buffer/array operations")

        # NULL Pointer validation
        if "null" in middle_lower:
            if not (has_null or has_pointer):
                return HeuristicResult(False, -0.3, "NULL Pointer should have pointer operations")

        # General Memory validation
        memory_score = sum([has_malloc, has_pointer, has_null, has_buffer, has_array])
        if memory_score == 0:
            return HeuristicResult(False, -0.4, "No memory-related patterns found")

        return HeuristicResult(True, 0.1 * memory_score, "Memory patterns confirmed")

    def validate_injection(self, code: str, middle_category: str) -> HeuristicResult:
        """Validate Injection category predictions."""
        has_sql = bool(self.INJECTION_PATTERNS["sql"].search(code))
        has_cmd = bool(self.INJECTION_PATTERNS["command"].search(code))
        has_xss = bool(self.INJECTION_PATTERNS["xss"].search(code))

        middle_lower = middle_category.lower()

        if "sql" in middle_lower and not has_sql:
            return HeuristicResult(False, -0.5, "SQL Injection requires SQL keywords")

        if "command" in middle_lower and not has_cmd:
            return HeuristicResult(False, -0.5, "Command Injection requires exec/system calls")

        if "xss" in middle_lower and not has_xss:
            return HeuristicResult(False, -0.4, "XSS requires DOM manipulation patterns")

        if not (has_sql or has_cmd or has_xss):
            return HeuristicResult(False, -0.3, "No injection patterns found")

        return HeuristicResult(True, 0.2, "Injection patterns confirmed")

    def validate_logic(self, code: str, middle_category: str) -> HeuristicResult:
        """Validate Logic category predictions."""
        has_auth = bool(self.LOGIC_PATTERNS["auth"].search(code))
        has_access = bool(self.LOGIC_PATTERNS["access_control"].search(code))

        # Check for memory patterns that might indicate misclassification
        has_memory = bool(self.MEMORY_PATTERNS["malloc_free"].search(code))
        has_pointer = bool(self.MEMORY_PATTERNS["pointer_ops"].search(code))

        # If code has strong memory patterns but weak logic patterns, likely misclassified
        if (has_memory or has_pointer) and not (has_auth or has_access):
            return HeuristicResult(False, -0.5, "Memory patterns suggest this is not Logic")

        if not (has_auth or has_access):
            return HeuristicResult(False, -0.2, "No authentication/authorization patterns found")

        return HeuristicResult(True, 0.1, "Logic patterns confirmed")

    def validate_crypto(self, code: str, middle_category: str) -> HeuristicResult:
        """Validate Crypto category predictions."""
        has_weak = bool(self.CRYPTO_PATTERNS["weak_algo"].search(code))
        has_crypto = bool(self.CRYPTO_PATTERNS["crypto_funcs"].search(code))
        has_random = bool(self.CRYPTO_PATTERNS["random"].search(code))

        if not (has_weak or has_crypto or has_random):
            return HeuristicResult(False, -0.3, "No cryptography patterns found")

        return HeuristicResult(True, 0.2, "Crypto patterns confirmed")

    def validate_input(self, code: str, middle_category: str) -> HeuristicResult:
        """Validate Input category predictions."""
        has_path = bool(self.INPUT_PATTERNS["path"].search(code))
        has_format = bool(self.INPUT_PATTERNS["format"].search(code))

        middle_lower = middle_category.lower()

        if "path" in middle_lower and not has_path:
            return HeuristicResult(False, -0.4, "Path Traversal requires path patterns")

        if "format" in middle_lower and not has_format:
            return HeuristicResult(False, -0.4, "Format String requires format specifiers")

        return HeuristicResult(True, 0.1, "Input patterns found")

    def validate(
        self,
        code: str,
        major_category: str,
        middle_category: str = ""
    ) -> HeuristicResult:
        """Validate a prediction using heuristics.

        Args:
            code: Source code to analyze
            major_category: Predicted major category
            middle_category: Predicted middle category (optional)

        Returns:
            HeuristicResult with validation status and confidence adjustment
        """
        major_lower = major_category.lower()

        if major_lower == "memory":
            return self.validate_memory(code, middle_category)
        elif major_lower == "injection":
            return self.validate_injection(code, middle_category)
        elif major_lower == "logic":
            return self.validate_logic(code, middle_category)
        elif major_lower == "crypto":
            return self.validate_crypto(code, middle_category)
        elif major_lower == "input":
            return self.validate_input(code, middle_category)
        elif major_lower == "benign":
            # For benign, check if there are any vulnerability patterns
            memory_patterns = any(p.search(code) for p in self.MEMORY_PATTERNS.values())
            injection_patterns = any(p.search(code) for p in self.INJECTION_PATTERNS.values())
            if memory_patterns or injection_patterns:
                return HeuristicResult(False, -0.2, "Potential vulnerability patterns found in benign code")
            return HeuristicResult(True, 0.1, "No obvious vulnerability patterns")

        return HeuristicResult(True, 0.0, "Unknown category")

    def suggest_category(self, code: str) -> List[Tuple[str, float]]:
        """Suggest likely categories based on code patterns.

        Returns:
            List of (category, confidence) tuples sorted by confidence
        """
        suggestions = []

        # Check Memory patterns
        memory_score = sum([
            bool(self.MEMORY_PATTERNS["malloc_free"].search(code)) * 0.3,
            bool(self.MEMORY_PATTERNS["pointer_ops"].search(code)) * 0.2,
            bool(self.MEMORY_PATTERNS["null_check"].search(code)) * 0.2,
            bool(self.MEMORY_PATTERNS["buffer_funcs"].search(code)) * 0.3,
        ])
        if memory_score > 0:
            suggestions.append(("Memory", memory_score))

        # Check Injection patterns
        injection_score = sum([
            bool(self.INJECTION_PATTERNS["sql"].search(code)) * 0.4,
            bool(self.INJECTION_PATTERNS["command"].search(code)) * 0.4,
            bool(self.INJECTION_PATTERNS["xss"].search(code)) * 0.3,
        ])
        if injection_score > 0:
            suggestions.append(("Injection", injection_score))

        # Check Logic patterns
        logic_score = sum([
            bool(self.LOGIC_PATTERNS["auth"].search(code)) * 0.3,
            bool(self.LOGIC_PATTERNS["access_control"].search(code)) * 0.2,
        ])
        # Reduce logic score if memory patterns are strong
        if memory_score > 0.3:
            logic_score *= 0.5
        if logic_score > 0:
            suggestions.append(("Logic", logic_score))

        # Check Crypto patterns
        crypto_score = sum([
            bool(self.CRYPTO_PATTERNS["weak_algo"].search(code)) * 0.4,
            bool(self.CRYPTO_PATTERNS["crypto_funcs"].search(code)) * 0.3,
            bool(self.CRYPTO_PATTERNS["random"].search(code)) * 0.2,
        ])
        if crypto_score > 0:
            suggestions.append(("Crypto", crypto_score))

        # Check Input patterns
        input_score = sum([
            bool(self.INPUT_PATTERNS["path"].search(code)) * 0.3,
            bool(self.INPUT_PATTERNS["format"].search(code)) * 0.3,
        ])
        if input_score > 0:
            suggestions.append(("Input", input_score))

        # Sort by confidence
        suggestions.sort(key=lambda x: x[1], reverse=True)

        # If no patterns found, suggest Benign
        if not suggestions:
            suggestions.append(("Benign", 0.5))

        return suggestions
