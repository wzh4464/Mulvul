"""Canonical CWE taxonomy for the MulVul mainline.

This module is the only source of truth for the executable mainline hierarchy.
All forward mappings are defined here. Reverse mappings are derived from the
forward definitions and must not be maintained separately elsewhere.
"""

from __future__ import annotations

import re
from typing import Iterable, Literal

BENIGN_LABEL = "Benign"
UNKNOWN_LABEL = "Unknown"
DEFAULT_MAJOR_LABEL = "Logic"
DEFAULT_MIDDLE_LABEL = "Other"
TaxonomyStage = Literal["major", "middle", "cwe"]

# Forward mappings are the only hand-maintained taxonomy definitions.
MAJOR_TO_MIDDLE: dict[str, list[str]] = {
    "Memory": [
        "Buffer Errors",
        "Memory Management",
        "Pointer Dereference",
        "Integer Errors",
    ],
    "Injection": ["Injection"],
    "Logic": [
        "Concurrency Issues",
        "Information Exposure",
        "Resource Management",
        "Access Control",
        "Other",
    ],
    "Input": ["Path Traversal", "Input Validation"],
    "Crypto": ["Cryptography Issues"],
}

MIDDLE_TO_CWE: dict[str, list[str]] = {
    "Buffer Errors": [
        "CWE-119",
        "CWE-120",
        "CWE-121",
        "CWE-122",
        "CWE-125",
        "CWE-131",
        "CWE-787",
        "CWE-805",
    ],
    "Memory Management": [
        "CWE-401",
        "CWE-415",
        "CWE-416",
        "CWE-772",
    ],
    "Pointer Dereference": ["CWE-476", "CWE-617"],
    "Integer Errors": ["CWE-189", "CWE-190", "CWE-191", "CWE-369"],
    "Injection": ["CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-94"],
    "Concurrency Issues": ["CWE-362", "CWE-667"],
    "Information Exposure": ["CWE-200", "CWE-209"],
    "Resource Management": ["CWE-399", "CWE-400", "CWE-770", "CWE-835"],
    "Access Control": ["CWE-264", "CWE-269", "CWE-284"],
    "Path Traversal": ["CWE-22", "CWE-59"],
    "Input Validation": ["CWE-20", "CWE-703"],
    "Cryptography Issues": [
        "CWE-254",
        "CWE-310",
        "CWE-311",
        "CWE-312",
        "CWE-326",
        "CWE-327",
        "CWE-330",
    ],
    "Other": [],
}


def _derive_middle_to_major(
    major_to_middle: dict[str, list[str]],
) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for major, middles in major_to_middle.items():
        for middle in middles:
            mapping[middle] = major
    return mapping


def _derive_cwe_to_middle(
    middle_to_cwe: dict[str, list[str]],
) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for middle, cwes in middle_to_cwe.items():
        for cwe in cwes:
            mapping[cwe] = middle
    return mapping


MIDDLE_TO_MAJOR: dict[str, str] = _derive_middle_to_major(MAJOR_TO_MIDDLE)
CWE_TO_MIDDLE: dict[str, str] = _derive_cwe_to_middle(MIDDLE_TO_CWE)

MAJOR_CATEGORIES = [*MAJOR_TO_MIDDLE.keys(), BENIGN_LABEL]
MIDDLE_CATEGORIES = list(MIDDLE_TO_CWE.keys())

# CWE descriptions for prompts and docs.
# Source: MITRE CWE (https://cwe.mitre.org/)
CWE_DESCRIPTIONS: dict[str, str] = {
    # Input Validation
    "CWE-20": "Improper Input Validation - insufficient validation of user input allowing malicious data",
    "CWE-22": "Path Traversal - accessing files outside intended directory via '../' sequences",
    "CWE-703": "Improper Check or Handling of Exceptional Conditions - failing to handle errors properly",
    # Injection
    "CWE-74": "Injection - improper neutralization of special elements in output used by downstream component",
    "CWE-77": "Command Injection - constructing commands using externally-influenced input",
    "CWE-78": "OS Command Injection - executing arbitrary system commands via shell",
    "CWE-79": "Cross-site Scripting (XSS) - injecting malicious scripts into web pages",
    "CWE-89": "SQL Injection - executing arbitrary SQL queries through untrusted input",
    "CWE-94": "Code Injection - improper control of code generation allowing arbitrary code execution",
    # Buffer Errors
    "CWE-119": "Buffer Overflow - operations exceed memory buffer bounds causing memory corruption",
    "CWE-120": "Classic Buffer Overflow - copying data without checking size of input",
    "CWE-121": "Stack-based Buffer Overflow - buffer overflow in stack memory",
    "CWE-122": "Heap-based Buffer Overflow - buffer overflow in heap memory",
    "CWE-125": "Out-of-bounds Read - reading beyond allocated memory boundaries",
    "CWE-131": "Incorrect Calculation of Buffer Size - miscalculating required buffer size",
    "CWE-787": "Out-of-bounds Write - writing beyond allocated memory boundaries",
    "CWE-805": "Buffer Access with Incorrect Length Value - accessing buffer with wrong length",
    # Memory Management
    "CWE-401": "Missing Release of Memory (Memory Leak) - not freeing allocated memory after use",
    "CWE-415": "Double Free - freeing memory that was already freed",
    "CWE-416": "Use After Free - accessing memory after it has been freed",
    "CWE-772": "Missing Release of Resource - not releasing resource after effective lifetime",
    # Pointer Issues
    "CWE-476": "NULL Pointer Dereference - accessing memory through null pointer",
    "CWE-617": "Reachable Assertion - assertion that can be triggered by attacker",
    # Integer Errors
    "CWE-189": "Numeric Errors - general numeric calculation problems (category)",
    "CWE-190": "Integer Overflow or Wraparound - arithmetic exceeds integer limits wrapping around",
    "CWE-191": "Integer Underflow - arithmetic goes below minimum value wrapping around",
    "CWE-369": "Divide By Zero - division or modulo operation with zero divisor",
    # Concurrency
    "CWE-362": "Race Condition - concurrent access to shared resource without proper synchronization",
    "CWE-667": "Improper Locking - incorrect use of locks leading to deadlock or race conditions",
    # Information Exposure
    "CWE-200": "Information Exposure - leaking sensitive data to unauthorized actors",
    "CWE-209": "Error Message Information Exposure - error messages revealing sensitive information",
    # Access Control
    "CWE-254": "Security Features - 7PK security features category",
    "CWE-264": "Permissions, Privileges, and Access Controls - improper permission management (category)",
    "CWE-269": "Improper Privilege Management - incorrect assignment or handling of privileges",
    "CWE-284": "Improper Access Control - failing to restrict access to authorized users",
    # Path/Link Issues
    "CWE-59": "Improper Link Resolution (Link Following) - following symbolic links to unintended files",
    # Resource Management
    "CWE-399": "Resource Management Errors - improper management of system resources (category)",
    "CWE-400": "Uncontrolled Resource Consumption - allowing excessive resource usage (DoS)",
    "CWE-770": "Allocation Without Limits or Throttling - allocating resources without caps or rate limits",
    "CWE-835": "Infinite Loop - loop with unreachable exit condition causing hang or DoS",
    # Cryptography
    "CWE-310": "Cryptographic Issues - general cryptography problems (category)",
    "CWE-311": "Missing Encryption of Sensitive Data - transmitting/storing sensitive data unencrypted",
    "CWE-312": "Cleartext Storage of Sensitive Information - storing passwords/keys in plaintext",
    "CWE-326": "Inadequate Encryption Strength - using weak encryption algorithms or key sizes",
    "CWE-327": "Use of Broken or Risky Cryptographic Algorithm - using deprecated/weak crypto",
    "CWE-330": "Use of Insufficiently Random Values - predictable random number generation",
}

_CWE_REGEX = re.compile(r"CWE-(\d+)")
_NODE_SUFFIX_REGEX = re.compile(r"[^a-z0-9]+")


def _slugify_node_suffix(label: str) -> str:
    normalized = _NODE_SUFFIX_REGEX.sub("_", label.lower()).strip("_")
    return normalized or "unknown"


def major_node_id(major: str) -> str:
    """Return the stable v2 node id for a major label."""

    return f"major_{_slugify_node_suffix(major)}"


def middle_node_id(middle: str) -> str:
    """Return the stable v2 node id for a middle label."""

    return f"middle_{_slugify_node_suffix(middle)}"


def cwe_node_id(cwe: str | int) -> str:
    """Return the stable v2 node id for a CWE label."""

    label = normalize_cwe_label(cwe)
    if label is None:
        raise ValueError(f"Invalid CWE label for node id: {cwe!r}")
    cwe_id = extract_cwe_id(label)
    if cwe_id is None:
        raise ValueError(f"Invalid CWE label for node id: {cwe!r}")
    return f"cwe_{cwe_id}"


def taxonomy_node_id(stage: TaxonomyStage, label: str) -> str:
    """Return the stable v2 node id for a taxonomy stage/label pair."""

    if stage == "major":
        return major_node_id(label)
    if stage == "middle":
        return middle_node_id(label)
    return cwe_node_id(label)


def extract_cwe_id(cwe_str: str | int) -> int | None:
    """Extract a numeric CWE ID from inputs like ``CWE-119`` or ``119``."""

    if isinstance(cwe_str, int):
        return cwe_str
    match = _CWE_REGEX.search(str(cwe_str))
    return int(match.group(1)) if match else None


def normalize_cwe_label(cwe: str | int) -> str | None:
    """Normalize a CWE value to the canonical ``CWE-<id>`` label."""

    cwe_id = extract_cwe_id(cwe)
    return f"CWE-{cwe_id}" if cwe_id is not None else None


def cwe_to_middle(cwe_codes: Iterable[str | int]) -> str:
    """Map a collection of CWE codes to a middle category."""

    for code in cwe_codes:
        label = normalize_cwe_label(code)
        if label and label in CWE_TO_MIDDLE:
            return CWE_TO_MIDDLE[label]
    return DEFAULT_MIDDLE_LABEL


def cwe_to_major(cwe_codes: Iterable[str | int]) -> str:
    """Map a collection of CWE codes to a major category."""

    middle = cwe_to_middle(cwe_codes)
    return MIDDLE_TO_MAJOR.get(middle, DEFAULT_MAJOR_LABEL)


def middle_to_major(middle: str) -> str:
    """Map a middle category to its major parent."""

    return MIDDLE_TO_MAJOR.get(middle, DEFAULT_MAJOR_LABEL)


def get_cwes_for_major(major: str) -> list[str]:
    """Get all canonical CWE labels that belong to a major category."""

    cwes: list[str] = []
    for middle in MAJOR_TO_MIDDLE.get(major, []):
        cwes.extend(MIDDLE_TO_CWE.get(middle, []))
    return cwes


def get_cwes_for_middle(middle: str) -> list[str]:
    """Get all canonical CWE labels that belong to a middle category."""

    return list(MIDDLE_TO_CWE.get(middle, []))


def validate_taxonomy() -> list[str]:
    """Return invariant violations for the canonical taxonomy."""

    errors: list[str] = []

    if BENIGN_LABEL in MAJOR_TO_MIDDLE:
        errors.append("Benign must not appear as a major node with descendants.")
    if BENIGN_LABEL in MIDDLE_TO_CWE:
        errors.append("Benign must not appear as a middle node with descendants.")

    seen_middles: dict[str, str] = {}
    for major, middles in MAJOR_TO_MIDDLE.items():
        for middle in middles:
            previous = seen_middles.get(middle)
            if previous and previous != major:
                errors.append(
                    f"Middle category {middle!r} is assigned to multiple majors: "
                    f"{previous!r}, {major!r}"
                )
            seen_middles[middle] = major

    orphan_middles = sorted(set(MIDDLE_TO_CWE) - set(seen_middles))
    if orphan_middles:
        errors.append(
            "Middle categories are missing a major parent: " + ", ".join(orphan_middles)
        )

    seen_cwes: dict[str, str] = {}
    for middle, cwes in MIDDLE_TO_CWE.items():
        for cwe in cwes:
            previous = seen_cwes.get(cwe)
            if previous and previous != middle:
                errors.append(
                    f"CWE {cwe!r} is assigned to multiple middles: "
                    f"{previous!r}, {middle!r}"
                )
            seen_cwes[cwe] = middle

    reverse_middle_errors = [
        middle
        for middle, major in MIDDLE_TO_MAJOR.items()
        if middle not in seen_middles or seen_middles[middle] != major
    ]
    if reverse_middle_errors:
        errors.append(
            "Reverse middle-to-major mapping is inconsistent for: "
            + ", ".join(sorted(reverse_middle_errors))
        )

    reverse_cwe_errors = [
        cwe
        for cwe, middle in CWE_TO_MIDDLE.items()
        if cwe not in seen_cwes or seen_cwes[cwe] != middle
    ]
    if reverse_cwe_errors:
        errors.append(
            "Reverse cwe-to-middle mapping is inconsistent for: "
            + ", ".join(sorted(reverse_cwe_errors))
        )

    major_node_ids = [major_node_id(major) for major in MAJOR_TO_MIDDLE]
    if len(major_node_ids) != len(set(major_node_ids)):
        errors.append("Major labels produce duplicate stable node ids.")

    middle_node_ids = [middle_node_id(middle) for middle in MIDDLE_TO_CWE]
    if len(middle_node_ids) != len(set(middle_node_ids)):
        errors.append("Middle labels produce duplicate stable node ids.")

    cwe_node_ids = [cwe_node_id(cwe) for cwe in seen_cwes]
    if len(cwe_node_ids) != len(set(cwe_node_ids)):
        errors.append("CWE labels produce duplicate stable node ids.")

    return errors
