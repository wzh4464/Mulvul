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
        "Initialization & Lifetime",
        "Type & Conversion Errors",
    ],
    "Injection": ["Injection"],
    "Logic": [
        "Concurrency Issues",
        "Information Exposure",
        "Resource Management",
        "Error Handling",
        "Control Flow & State",
        "Protection Mechanisms",
        "Access Control",
        "Other",
    ],
    "Input": ["Path Traversal", "Input Validation", "External References"],
    "Crypto": ["Cryptography Issues"],
    "Authentication": ["Authentication", "Credential Handling"],
    "Authorization & Exposure": ["Authorization", "Permissions & Exposure"],
    "Cryptographic Trust": ["Trust Verification", "Request Authenticity"],
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
        "CWE-672",
        "CWE-763",
        "CWE-772",
    ],
    "Pointer Dereference": ["CWE-476", "CWE-617", "CWE-823", "CWE-824"],
    "Integer Errors": [
        "CWE-129",
        "CWE-189",
        "CWE-190",
        "CWE-191",
        "CWE-193",
        "CWE-369",
        "CWE-681",
        "CWE-682",
    ],
    "Initialization & Lifetime": ["CWE-457", "CWE-665", "CWE-908", "CWE-909"],
    "Type & Conversion Errors": ["CWE-704", "CWE-843"],
    "Injection": [
        "CWE-74",
        "CWE-77",
        "CWE-78",
        "CWE-79",
        "CWE-88",
        "CWE-89",
        "CWE-93",
        "CWE-94",
        "CWE-113",
        "CWE-116",
        "CWE-134",
        "CWE-172",
        "CWE-444",
        "CWE-707",
    ],
    "Concurrency Issues": ["CWE-362", "CWE-667"],
    "Information Exposure": ["CWE-200", "CWE-203", "CWE-209", "CWE-212", "CWE-532"],
    "Resource Management": [
        "CWE-399",
        "CWE-400",
        "CWE-404",
        "CWE-417",
        "CWE-664",
        "CWE-770",
        "CWE-834",
        "CWE-835",
    ],
    "Error Handling": ["CWE-252", "CWE-388", "CWE-674", "CWE-703", "CWE-754", "CWE-755"],
    "Control Flow & State": ["CWE-17", "CWE-19", "CWE-361", "CWE-670", "CWE-697"],
    "Protection Mechanisms": ["CWE-16", "CWE-693", "CWE-1021"],
    "Access Control": ["CWE-264", "CWE-269", "CWE-284"],
    "Path Traversal": ["CWE-22", "CWE-59"],
    "Input Validation": ["CWE-20", "CWE-241", "CWE-502"],
    "External References": ["CWE-61", "CWE-426", "CWE-601", "CWE-611", "CWE-918"],
    "Cryptography Issues": [
        "CWE-254",
        "CWE-310",
        "CWE-311",
        "CWE-312",
        "CWE-320",
        "CWE-326",
        "CWE-327",
        "CWE-330",
        "CWE-331",
    ],
    "Authentication": ["CWE-287", "CWE-290", "CWE-294", "CWE-307", "CWE-613"],
    "Credential Handling": ["CWE-255", "CWE-522", "CWE-798"],
    "Authorization": ["CWE-273", "CWE-285", "CWE-639", "CWE-862", "CWE-863"],
    "Permissions & Exposure": ["CWE-276", "CWE-281", "CWE-552", "CWE-668", "CWE-732"],
    "Trust Verification": ["CWE-295", "CWE-345", "CWE-346", "CWE-347", "CWE-349", "CWE-354"],
    "Request Authenticity": ["CWE-352"],
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

CWE_DESCRIPTIONS.update(
    {
        # Logic and control flow
        "CWE-16": "Configuration - insecure or incorrect security-relevant configuration (category)",
        "CWE-17": "Code - general code-related weaknesses affecting program behavior (category)",
        "CWE-19": "Data Processing Errors - flaws in how data is represented, transformed, or interpreted (category)",
        "CWE-252": "Unchecked Return Value - ignoring failures or error codes from important operations",
        "CWE-361": "Time and State - flaws caused by unsafe assumptions about timing or state transitions",
        "CWE-388": "Error Handling - improper detection, propagation, or handling of error conditions",
        "CWE-404": "Improper Resource Shutdown or Release - failing to close, flush, or release resources safely",
        "CWE-417": "Communication Channel Errors - insecure or inconsistent use of communication channels",
        "CWE-664": "Improper Control of a Resource Through its Lifetime - mishandling resource state across allocation, use, and release",
        "CWE-670": "Always-Incorrect Control Flow Implementation - control flow logic that is systematically wrong",
        "CWE-674": "Uncontrolled Recursion - recursion without adequate termination or depth limits",
        "CWE-693": "Protection Mechanism Failure - a security control exists but is missing, bypassed, or ineffective",
        "CWE-697": "Incorrect Comparison - using the wrong comparison logic for security-critical decisions",
        "CWE-754": "Improper Check for Unusual or Exceptional Conditions - missing checks for rare or error states",
        "CWE-755": "Improper Handling of Exceptional Conditions - failing to recover safely from unexpected states",
        "CWE-834": "Excessive Iteration - loops or repeated work that can be driven to consume excessive resources",
        "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames - allowing UI overlay or framing attacks",
        # Memory, type, and initialization
        "CWE-129": "Improper Validation of Array Index - using an index without confirming it is within bounds",
        "CWE-193": "Off-by-one Error - boundary logic that is short or long by a single element",
        "CWE-457": "Use of Uninitialized Variable - reading from variables before they are initialized",
        "CWE-665": "Improper Initialization - leaving objects or resources in an unsafe initial state",
        "CWE-672": "Operation on a Resource after Expiration or Release - using a resource outside its valid lifetime",
        "CWE-681": "Incorrect Conversion between Numeric Types - lossy or unsafe numeric conversions",
        "CWE-682": "Incorrect Calculation - mistakes in arithmetic or derived values affecting correctness or safety",
        "CWE-704": "Incorrect Type Conversion or Cast - converting values between incompatible types",
        "CWE-763": "Release of Invalid Pointer or Reference - freeing or releasing something that is not a valid owned resource",
        "CWE-823": "Use of Out-of-range Pointer Offset - pointer arithmetic that escapes the valid object range",
        "CWE-824": "Access of Uninitialized Pointer - dereferencing a pointer before it has been assigned safely",
        "CWE-843": "Type Confusion - accessing a resource through an incompatible or unexpected type",
        "CWE-908": "Use of Uninitialized Resource - consuming resources before required setup is complete",
        "CWE-909": "Missing Initialization of Resource - failing to initialize a resource before exposing it to use",
        # Input and external references
        "CWE-61": "UNIX Symbolic Link Following - trusting symlinks and reaching unintended files or locations",
        "CWE-241": "Improper Handling of Unexpected Data Type - accepting or processing values of the wrong type",
        "CWE-426": "Untrusted Search Path - resolving executables or files through attacker-influenced lookup paths",
        "CWE-502": "Deserialization of Untrusted Data - loading attacker-controlled serialized data into executable objects",
        "CWE-601": "Open Redirect - redirecting users to untrusted destinations",
        "CWE-611": "XML External Entity Reference - resolving attacker-controlled external entities during XML parsing",
        "CWE-918": "Server-Side Request Forgery - making server-side requests to attacker-chosen destinations",
        # Injection family
        "CWE-88": "Argument Injection - injecting extra command arguments through untrusted input",
        "CWE-93": "CRLF Injection - injecting carriage-return or line-feed delimiters into structured data",
        "CWE-113": "HTTP Request/Response Splitting - injecting CRLF into HTTP headers or response boundaries",
        "CWE-116": "Improper Encoding or Escaping of Output - failing to encode output for its destination context",
        "CWE-134": "Use of Externally-Controlled Format String - attacker input controls a format string or formatter behavior",
        "CWE-172": "Encoding Error - incorrect transformations between encodings cause security failures",
        "CWE-444": "HTTP Request/Response Smuggling - parser disagreement lets attackers smuggle hidden requests",
        "CWE-707": "Improper Neutralization - failing to neutralize special elements before downstream interpretation",
        # Authentication and credential handling
        "CWE-255": "Credentials Management Errors - insecure creation, storage, rotation, or use of credentials (category)",
        "CWE-273": "Improper Check for Dropped Privileges - assuming privileges were reduced without verifying the result",
        "CWE-285": "Improper Authorization - granting access without adequate authorization checks",
        "CWE-287": "Improper Authentication - failing to confirm identity before performing sensitive actions",
        "CWE-290": "Authentication Bypass by Spoofing - trusting spoofable identity attributes or signals",
        "CWE-294": "Authentication Bypass by Capture-replay - accepting replayed authentication material as fresh",
        "CWE-307": "Improper Restriction of Excessive Authentication Attempts - missing throttling or lockouts for repeated guesses",
        "CWE-522": "Insufficiently Protected Credentials - storing or transmitting credentials without adequate protection",
        "CWE-613": "Insufficient Session Expiration - sessions remain valid for too long or after they should be revoked",
        "CWE-798": "Use of Hard-coded Credentials - embedding secrets directly in code or shipped artifacts",
        # Authorization and exposure
        "CWE-276": "Incorrect Default Permissions - shipping resources with overly permissive default access",
        "CWE-281": "Improper Preservation of Permissions - permissions change unexpectedly across copies, moves, or updates",
        "CWE-552": "Files or Directories Accessible to External Parties - exposing files to users or services that should not reach them",
        "CWE-639": "Authorization Bypass Through User-Controlled Key - using attacker-controlled identifiers to reach another user's data",
        "CWE-668": "Exposure of Resource to Wrong Sphere - making a resource visible outside its intended trust boundary",
        "CWE-732": "Incorrect Permission Assignment for Critical Resource - misconfiguring privileges on security-sensitive resources",
        "CWE-862": "Missing Authorization - performing privileged actions without checking authorization at all",
        "CWE-863": "Incorrect Authorization - checking authorization incorrectly or against the wrong policy",
        # Information exposure
        "CWE-203": "Observable Discrepancy - differences in responses leak information about internal state or secrets",
        "CWE-212": "Improper Removal of Sensitive Information Before Storage or Transfer - failing to scrub secrets before persistence or transmission",
        "CWE-532": "Insertion of Sensitive Information into Log File - writing secrets into logs or other observability channels",
        # Cryptographic trust
        "CWE-295": "Improper Certificate Validation - accepting certificates without fully validating trust requirements",
        "CWE-320": "Key Management Errors - mishandling cryptographic keys across generation, storage, rotation, or destruction",
        "CWE-331": "Insufficient Entropy - generating secrets or tokens from predictable randomness",
        "CWE-345": "Insufficient Verification of Data Authenticity - trusting data without verifying origin or authenticity",
        "CWE-346": "Origin Validation Error - failing to verify that data or requests came from an allowed origin",
        "CWE-347": "Improper Verification of Cryptographic Signature - accepting data without validating its signature correctly",
        "CWE-349": "Acceptance of Extraneous Untrusted Data With Trusted Data - mixing attacker-controlled data into trusted structures",
        "CWE-352": "Cross-Site Request Forgery - tricking a victim browser into sending unintended authenticated requests",
        "CWE-354": "Improper Validation of Integrity Check Value - trusting checksums or integrity values without validating them safely",
    }
)

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
