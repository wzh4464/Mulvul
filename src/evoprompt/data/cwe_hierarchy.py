"""Hierarchical CWE category mapping for MulVul.

Three-level hierarchy:
- Major (5): Memory, Injection, Logic, Input, Crypto
- Middle (10): Buffer Errors, Memory Management, etc.
- CWE (119+): Specific CWE IDs
"""

from typing import Dict, List, Optional, Tuple
import re

# Major categories (for Router)
MAJOR_CATEGORIES = ["Memory", "Injection", "Logic", "Input", "Crypto", "Benign"]

# Middle categories (for Detector output)
MIDDLE_CATEGORIES = [
    "Buffer Errors",
    "Memory Management",
    "Pointer Dereference",
    "Integer Errors",
    "Injection",
    "Concurrency Issues",
    "Path Traversal",
    "Cryptography Issues",
    "Information Exposure",
    "Resource Management",
    "Access Control",
    "Input Validation",
    "Other",
    "Benign",
]

# Middle -> Major mapping
MIDDLE_TO_MAJOR: Dict[str, str] = {
    "Buffer Errors": "Memory",
    "Memory Management": "Memory",
    "Pointer Dereference": "Memory",
    "Integer Errors": "Memory",
    "Injection": "Injection",
    "Concurrency Issues": "Logic",
    "Path Traversal": "Input",
    "Cryptography Issues": "Crypto",
    "Information Exposure": "Logic",
    "Resource Management": "Logic",
    "Access Control": "Logic",
    "Input Validation": "Input",
    "Other": "Logic",
    "Benign": "Benign",
}

# CWE -> Middle mapping (comprehensive for Primevul)
CWE_TO_MIDDLE: Dict[int, str] = {
    # Buffer Errors
    119: "Buffer Errors",  # Improper Restriction of Operations within the Bounds of a Memory Buffer
    120: "Buffer Errors",  # Classic Buffer Overflow
    121: "Buffer Errors",  # Stack-based Buffer Overflow
    122: "Buffer Errors",  # Heap-based Buffer Overflow
    125: "Buffer Errors",  # Out-of-bounds Read
    131: "Buffer Errors",  # Incorrect Calculation of Buffer Size
    787: "Buffer Errors",  # Out-of-bounds Write
    805: "Buffer Errors",  # Buffer Access with Incorrect Length Value

    # Memory Management
    416: "Memory Management",  # Use After Free
    415: "Memory Management",  # Double Free
    401: "Memory Management",  # Missing Release of Memory after Effective Lifetime
    772: "Memory Management",  # Missing Release of Resource after Effective Lifetime

    # Pointer Dereference
    476: "Pointer Dereference",  # NULL Pointer Dereference
    617: "Pointer Dereference",  # Reachable Assertion

    # Integer Errors
    190: "Integer Errors",  # Integer Overflow or Wraparound
    191: "Integer Errors",  # Integer Underflow
    189: "Integer Errors",  # Numeric Errors
    369: "Integer Errors",  # Divide By Zero

    # Injection
    74: "Injection",   # Injection
    77: "Injection",   # Command Injection
    78: "Injection",   # OS Command Injection
    79: "Injection",   # Cross-site Scripting (XSS)
    89: "Injection",   # SQL Injection
    94: "Injection",   # Code Injection

    # Concurrency Issues
    362: "Concurrency Issues",  # Race Condition
    667: "Concurrency Issues",  # Improper Locking

    # Path Traversal
    22: "Path Traversal",  # Path Traversal
    59: "Path Traversal",  # Improper Link Resolution Before File Access

    # Cryptography Issues
    310: "Cryptography Issues",  # Cryptographic Issues
    311: "Cryptography Issues",  # Missing Encryption of Sensitive Data
    312: "Cryptography Issues",  # Cleartext Storage of Sensitive Information
    326: "Cryptography Issues",  # Inadequate Encryption Strength
    327: "Cryptography Issues",  # Use of a Broken or Risky Cryptographic Algorithm
    330: "Cryptography Issues",  # Use of Insufficiently Random Values
    254: "Cryptography Issues",  # Security Features

    # Information Exposure
    200: "Information Exposure",  # Information Exposure
    209: "Information Exposure",  # Information Exposure Through an Error Message

    # Resource Management
    399: "Resource Management",  # Resource Management Errors
    400: "Resource Management",  # Uncontrolled Resource Consumption
    770: "Resource Management",  # Allocation of Resources Without Limits
    835: "Resource Management",  # Loop with Unreachable Exit Condition

    # Access Control
    264: "Access Control",  # Permissions, Privileges, and Access Controls
    284: "Access Control",  # Improper Access Control
    269: "Access Control",  # Improper Privilege Management

    # Input Validation
    20: "Input Validation",  # Improper Input Validation
    703: "Input Validation",  # Improper Check or Handling of Exceptional Conditions
}

# CWE descriptions for prompts
CWE_DESCRIPTIONS: Dict[int, str] = {
    119: "Buffer overflow - operations exceed memory buffer bounds",
    120: "Classic buffer overflow - copying data without bounds checking",
    125: "Out-of-bounds read - reading beyond allocated memory",
    787: "Out-of-bounds write - writing beyond allocated memory",
    416: "Use after free - accessing memory after it has been freed",
    415: "Double free - freeing memory that was already freed",
    476: "NULL pointer dereference - accessing memory through null pointer",
    190: "Integer overflow - arithmetic operation exceeds integer limits",
    362: "Race condition - concurrent access to shared resource",
    78: "OS command injection - executing arbitrary system commands",
    89: "SQL injection - executing arbitrary SQL queries",
    22: "Path traversal - accessing files outside intended directory",
    200: "Information exposure - leaking sensitive data",
    20: "Improper input validation - insufficient validation of user input",
}

_CWE_REGEX = re.compile(r"CWE-(\d+)")


def extract_cwe_id(cwe_str: str) -> Optional[int]:
    """Extract CWE ID from string like 'CWE-119'."""
    m = _CWE_REGEX.search(str(cwe_str))
    return int(m.group(1)) if m else None


def cwe_to_middle(cwe_codes: List[str]) -> str:
    """Map CWE codes to middle category."""
    for code in cwe_codes:
        cwe_id = extract_cwe_id(code)
        if cwe_id and cwe_id in CWE_TO_MIDDLE:
            return CWE_TO_MIDDLE[cwe_id]
    return "Other"


def cwe_to_major(cwe_codes: List[str]) -> str:
    """Map CWE codes to major category."""
    middle = cwe_to_middle(cwe_codes)
    return MIDDLE_TO_MAJOR.get(middle, "Logic")


def middle_to_major(middle: str) -> str:
    """Map middle category to major category."""
    return MIDDLE_TO_MAJOR.get(middle, "Logic")


def get_cwes_for_major(major: str) -> List[int]:
    """Get all CWE IDs that belong to a major category."""
    cwes = []
    for cwe_id, middle in CWE_TO_MIDDLE.items():
        if MIDDLE_TO_MAJOR.get(middle) == major:
            cwes.append(cwe_id)
    return cwes


def get_cwes_for_middle(middle: str) -> List[int]:
    """Get all CWE IDs that belong to a middle category."""
    return [cwe_id for cwe_id, m in CWE_TO_MIDDLE.items() if m == middle]
