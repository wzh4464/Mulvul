"""Canonical CWE taxonomy for the MulVul mainline.

This module is the only source of truth for the executable mainline hierarchy.
All forward mappings are defined here. Reverse mappings are derived from the
forward definitions and must not be maintained separately elsewhere.
"""

from __future__ import annotations

import re
from typing import Iterable

BENIGN_LABEL = "Benign"
UNKNOWN_LABEL = "Unknown"
DEFAULT_MAJOR_LABEL = "Logic"
DEFAULT_MIDDLE_LABEL = "Other"

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
CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-20": "Improper input validation - insufficient validation of user input",
    "CWE-22": "Path traversal - accessing files outside intended directory",
    "CWE-78": "OS command injection - executing arbitrary system commands",
    "CWE-89": "SQL injection - executing arbitrary SQL queries",
    "CWE-119": "Buffer overflow - operations exceed memory buffer bounds",
    "CWE-120": "Classic buffer overflow - copying data without bounds checking",
    "CWE-125": "Out-of-bounds read - reading beyond allocated memory",
    "CWE-190": "Integer overflow - arithmetic operation exceeds integer limits",
    "CWE-200": "Information exposure - leaking sensitive data",
    "CWE-362": "Race condition - concurrent access to shared resource",
    "CWE-415": "Double free - freeing memory that was already freed",
    "CWE-416": "Use after free - accessing memory after it has been freed",
    "CWE-476": "NULL pointer dereference - accessing memory through null pointer",
    "CWE-787": "Out-of-bounds write - writing beyond allocated memory",
}

_CWE_REGEX = re.compile(r"CWE-(\d+)")


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
            "Middle categories are missing a major parent: "
            + ", ".join(orphan_middles)
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

    return errors
