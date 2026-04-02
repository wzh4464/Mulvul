# CWE Research Concepts mapping and utilities
from typing import List, Optional, Tuple
import re

# Research Concepts (0-10)
RESEARCH_CONCEPTS = {
    0: "No Vulnerability",
    1: "Improper Access Control",
    2: "Improper Interaction Between Multiple Correctly-Behaving Entities",
    3: "Improper Control of a Resource Through its Lifetime",
    4: "Incorrect Calculation",
    5: "Insufficient Control Flow Management",
    6: "Protection Mechanism Failure",
    7: "Incorrect Comparison",
    8: "Improper Check or Handling of Exceptional Conditions",
    9: "Improper Neutralization",
    10: "Improper Adherence to Coding Standards",
}

# Specific CWE -> Research Concept ID
_SPECIFIC_CWE_TO_CONCEPT = {
    # 1 Access Control
    "CWE-22": 1, "CWE-23": 1, "CWE-36": 1, "CWE-284": 1, "CWE-285": 1, "CWE-862": 1, "CWE-863": 1,
    # 2 Interaction / Concurrency
    "CWE-362": 2, "CWE-367": 2, "CWE-364": 2, "CWE-435": 2,
    # 3 Resource lifetime (memory/bounds/ptr)
    "CWE-119": 3, "CWE-120": 3, "CWE-121": 3, "CWE-122": 3, "CWE-125": 3, "CWE-126": 3, "CWE-127": 3,
    "CWE-131": 3, "CWE-401": 3, "CWE-415": 3, "CWE-416": 3, "CWE-476": 3, "CWE-664": 3, "CWE-787": 3,
    # 4 Incorrect Calculation / Integer
    "CWE-190": 4, "CWE-191": 4, "CWE-192": 4, "CWE-193": 4, "CWE-369": 4, "CWE-682": 4,
    # 5 Control flow
    "CWE-691": 5, "CWE-670": 5, "CWE-617": 5,
    # 6 Protection mechanism / Crypto
    "CWE-693": 6, "CWE-311": 6, "CWE-312": 6, "CWE-327": 6, "CWE-330": 6,
    # 7 Incorrect comparison
    "CWE-697": 7, "CWE-595": 7, "CWE-486": 7,
    # 8 Exceptional conditions
    "CWE-252": 8, "CWE-248": 8, "CWE-703": 8, "CWE-754": 8, "CWE-755": 8,
    # 9 Neutralization / Injection / Validation
    "CWE-20": 9, "CWE-74": 9, "CWE-78": 9, "CWE-79": 9, "CWE-89": 9, "CWE-94": 9, "CWE-707": 9, "CWE-116": 9,
    # 10 Coding standards
    "CWE-710": 10, "CWE-561": 10, "CWE-563": 10,
}

_CWE_ID_REGEX = re.compile(r"CWE-(\d+)")


def concept_id_to_name(concept_id: int) -> str:
    return RESEARCH_CONCEPTS.get(concept_id, RESEARCH_CONCEPTS[0])


def all_concepts_enumeration() -> str:
    return "\n".join([f"{k}: {v}" for k, v in RESEARCH_CONCEPTS.items()])


def normalize_cwe_id(cwe: str) -> Optional[str]:
    if not cwe:
        return None
    cwe = cwe.strip()
    m = _CWE_ID_REGEX.search(cwe)
    if m:
        return f"CWE-{int(m.group(1))}"
    if cwe.isdigit():
        return f"CWE-{int(cwe)}"
    return None


def map_single_cwe_to_concept_id(cwe: str) -> int:
    norm = normalize_cwe_id(cwe)
    if not norm:
        return 0
    return _SPECIFIC_CWE_TO_CONCEPT.get(norm, 0)


def map_cwe_list_to_concept_id(cwe_codes: List[str]) -> int:
    if not cwe_codes:
        return 0
    # Pick first recognized mapping; could be improved with priority rules
    for code in cwe_codes:
        cid = map_single_cwe_to_concept_id(code)
        if cid != 0:
            return cid
    return 0


def parse_concept_from_response(text: str) -> Optional[int]:
    if not text:
        return None
    s = text.strip()
    # Try number 0-10
    m = re.search(r"\b(\d{1,2})\b", s)
    if m:
        try:
            n = int(m.group(1))
            if 0 <= n <= 10:
                return n
        except ValueError:
            pass
    # Try name match (case-insensitive)
    low = s.lower()
    for cid, name in RESEARCH_CONCEPTS.items():
        if name.lower() in low:
            return cid
    # Try to detect a CWE ID and map
    m2 = _CWE_ID_REGEX.search(s)
    if m2:
        return map_single_cwe_to_concept_id(m2.group(0))
    return None