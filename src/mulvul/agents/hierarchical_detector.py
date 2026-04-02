"""Hierarchical Vulnerability Detector.

Three-level cascade detection:
1. Major: Memory, Injection, Logic, Input, Crypto
2. Middle: Buffer Errors, Memory Management, etc.
3. CWE: CWE-119, CWE-416, etc.

Each level uses top-k routing to the next level.
CWEs with < MIN_CWE_SAMPLES samples fallback to Middle level.
"""

import json
import os
import re
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

# Minimum samples required for CWE-level detection
MIN_CWE_SAMPLES = 50


@dataclass
class HierarchicalResult:
    """Result of hierarchical detection."""
    major: str
    major_confidence: float
    middle: str
    middle_confidence: float
    cwe: str
    cwe_confidence: float
    evidence: str
    path: List[Tuple[str, float]] = field(default_factory=list)  # Detection path
    raw_responses: Dict[str, str] = field(default_factory=dict)


# CWE Hierarchy Definition
MAJOR_TO_MIDDLE = {
    "Memory": ["Buffer Errors", "Memory Management", "Pointer Dereference", "Integer Errors"],
    "Injection": ["Injection"],
    "Logic": ["Concurrency Issues", "Information Exposure", "Resource Management", "Access Control", "Other"],
    "Input": ["Path Traversal", "Input Validation"],
    "Crypto": ["Cryptography Issues"],
}

MIDDLE_TO_CWE = {
    "Buffer Errors": ["CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-805"],
    "Memory Management": ["CWE-416", "CWE-415", "CWE-401", "CWE-772"],
    "Pointer Dereference": ["CWE-476", "CWE-617"],
    "Integer Errors": ["CWE-190", "CWE-191", "CWE-189", "CWE-369"],
    "Injection": ["CWE-78", "CWE-89", "CWE-79", "CWE-94", "CWE-77"],
    "Concurrency Issues": ["CWE-362", "CWE-667"],
    "Information Exposure": ["CWE-200", "CWE-209"],
    "Resource Management": ["CWE-399", "CWE-400", "CWE-770", "CWE-835"],
    "Access Control": ["CWE-264", "CWE-284", "CWE-269"],
    "Path Traversal": ["CWE-22", "CWE-59"],
    "Input Validation": ["CWE-20", "CWE-703"],
    "Cryptography Issues": ["CWE-310", "CWE-327", "CWE-330", "CWE-311"],
    "Other": [],
}

# Reverse mappings
CWE_TO_MIDDLE = {}
for middle, cwes in MIDDLE_TO_CWE.items():
    for cwe in cwes:
        CWE_TO_MIDDLE[cwe] = middle

MIDDLE_TO_MAJOR = {}
for major, middles in MAJOR_TO_MIDDLE.items():
    for middle in middles:
        MIDDLE_TO_MAJOR[middle] = major


def load_fallback_list(path: str = "data/cwe_fallback_list.json") -> Tuple[Set[str], Dict[str, str]]:
    """Load CWE fallback list.

    Returns:
        valid_cwes: Set of CWEs with enough samples for detection
        fallback_map: Dict mapping CWE -> Middle category for fallback
    """
    valid_cwes = set()
    fallback_map = {}

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        valid_cwes = {item["cwe"] for item in data.get("valid_cwes", [])}
        fallback_map = {cwe: info["middle"] for cwe, info in data.get("fallback_to_middle", {}).items()}
    else:
        # Fallback: use all CWEs in MIDDLE_TO_CWE
        for middle, cwes in MIDDLE_TO_CWE.items():
            for cwe in cwes:
                valid_cwes.add(cwe)

    return valid_cwes, fallback_map


# Load fallback list at module level
VALID_CWES, CWE_FALLBACK_MAP = load_fallback_list()


class LevelDetector:
    """Detector for a specific level (Major/Middle/CWE)."""

    def __init__(
        self,
        level: str,  # "major", "middle", "cwe"
        target: str,  # e.g., "Memory", "Buffer Errors", "CWE-119"
        llm_client,
        prompt: str,
        candidates: List[str],  # Possible outputs
        retriever=None,
    ):
        self.level = level
        self.target = target
        self.llm_client = llm_client
        self.prompt = prompt
        self.candidates = candidates
        self.retriever = retriever

    def detect(self, code: str, top_k: int = 2) -> List[Tuple[str, float]]:
        """Detect and return top-k candidates with confidence."""
        # Retrieve evidence
        evidence = self._retrieve_evidence(code)

        # Format prompt
        candidates_str = ", ".join(self.candidates)
        prompt = self.prompt.format(
            code=code[:4000],
            evidence=evidence,
            candidates=candidates_str,
        )

        # Query LLM
        response = self.llm_client.generate(prompt)

        # Parse response
        return self._parse_response(response, top_k)

    def _retrieve_evidence(self, code: str) -> str:
        if not self.retriever:
            return "No evidence available."

        if self.level == "major":
            samples = self.retriever.retrieve_from_category(code, self.target, top_k=3)
        elif self.level == "middle":
            samples = self.retriever.retrieve_from_middle(code, self.target, top_k=3)
        else:  # cwe
            samples = self.retriever.retrieve_from_cwe(code, self.target, top_k=3)

        if not samples:
            return "No similar examples found."

        lines = []
        for i, s in enumerate(samples[:3], 1):
            lines.append(f"Example {i} [{s.get('cwe', '')}]: {s['code'][:300]}...")
        return "\n".join(lines)

    def _parse_response(self, response: str, top_k: int) -> List[Tuple[str, float]]:
        """Parse LLM response to extract predictions."""
        try:
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                data = json.loads(json_match.group())
                predictions = data.get("predictions", [])
                return [
                    (p.get("category", p.get("cwe", "Unknown")), float(p.get("confidence", 0.5)))
                    for p in predictions[:top_k]
                ]
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback: keyword matching
        results = []
        response_lower = response.lower()
        for candidate in self.candidates:
            if candidate.lower() in response_lower:
                pos = response_lower.find(candidate.lower())
                score = 1.0 - (pos / max(len(response_lower), 1))
                results.append((candidate, min(score, 0.9)))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k] if results else [("Benign", 0.5)]


class HierarchicalDetector:
    """Three-level hierarchical vulnerability detector."""

    def __init__(
        self,
        llm_client,
        retriever=None,
        major_prompt: str = None,
        middle_prompts: Dict[str, str] = None,
        cwe_prompts: Dict[str, str] = None,
        top_k: int = 2,
    ):
        self.llm_client = llm_client
        self.retriever = retriever
        self.top_k = top_k

        # Default prompts
        self.major_prompt = major_prompt or self._default_major_prompt()
        self.middle_prompts = middle_prompts or {}
        self.cwe_prompts = cwe_prompts or {}

        # Build detectors
        self._build_detectors()

    def _build_detectors(self):
        """Build all level detectors."""
        # Major detector
        self.major_detector = LevelDetector(
            level="major",
            target="all",
            llm_client=self.llm_client,
            prompt=self.major_prompt,
            candidates=list(MAJOR_TO_MIDDLE.keys()) + ["Benign"],
            retriever=self.retriever,
        )

        # Middle detectors (one per major)
        self.middle_detectors = {}
        for major, middles in MAJOR_TO_MIDDLE.items():
            prompt = self.middle_prompts.get(major, self._default_middle_prompt(major))
            self.middle_detectors[major] = LevelDetector(
                level="middle",
                target=major,
                llm_client=self.llm_client,
                prompt=prompt,
                candidates=middles + ["Benign"],
                retriever=self.retriever,
            )

        # CWE detectors (one per middle)
        self.cwe_detectors = {}
        for middle, cwes in MIDDLE_TO_CWE.items():
            if not cwes:  # Skip if no CWEs
                continue
            prompt = self.cwe_prompts.get(middle, self._default_cwe_prompt(middle))
            self.cwe_detectors[middle] = LevelDetector(
                level="cwe",
                target=middle,
                llm_client=self.llm_client,
                prompt=prompt,
                candidates=cwes + ["Benign"],
                retriever=self.retriever,
            )

    def detect(self, code: str) -> HierarchicalResult:
        """Run hierarchical detection."""
        path = []

        # Level 1: Major detection
        major_results = self.major_detector.detect(code, top_k=self.top_k)
        path.append(("major", major_results))

        if not major_results or major_results[0][0] == "Benign":
            return HierarchicalResult(
                major="Benign", major_confidence=major_results[0][1] if major_results else 0.5,
                middle="Benign", middle_confidence=0.0,
                cwe="Benign", cwe_confidence=0.0,
                evidence="", path=path,
            )

        # Level 2: Middle detection (for top-k majors)
        middle_results = []
        for major, conf in major_results[:self.top_k]:
            if major == "Benign" or major not in self.middle_detectors:
                continue
            results = self.middle_detectors[major].detect(code, top_k=self.top_k)
            for middle, m_conf in results:
                middle_results.append((middle, m_conf * conf, major))

        middle_results.sort(key=lambda x: x[1], reverse=True)
        path.append(("middle", middle_results))

        if not middle_results or middle_results[0][0] == "Benign":
            return HierarchicalResult(
                major=major_results[0][0], major_confidence=major_results[0][1],
                middle="Benign", middle_confidence=0.0,
                cwe="Benign", cwe_confidence=0.0,
                evidence="", path=path,
            )

        # Level 3: CWE detection (for top-k middles)
        cwe_results = []
        for middle, conf, major in middle_results[:self.top_k]:
            if middle == "Benign" or middle not in self.cwe_detectors:
                # No CWE level for this middle, use middle as final
                cwe_results.append((middle, conf, middle, major))
                continue
            results = self.cwe_detectors[middle].detect(code, top_k=self.top_k)
            for cwe, c_conf in results:
                cwe_results.append((cwe, c_conf * conf, middle, major))

        cwe_results.sort(key=lambda x: x[1], reverse=True)
        path.append(("cwe", cwe_results))

        if not cwe_results:
            return HierarchicalResult(
                major=major_results[0][0], major_confidence=major_results[0][1],
                middle=middle_results[0][0], middle_confidence=middle_results[0][1],
                cwe="Unknown", cwe_confidence=0.0,
                evidence="", path=path,
            )

        best_cwe, best_conf, best_middle, best_major = cwe_results[0]

        return HierarchicalResult(
            major=best_major,
            major_confidence=major_results[0][1],
            middle=best_middle,
            middle_confidence=middle_results[0][1],
            cwe=best_cwe,
            cwe_confidence=best_conf,
            evidence="",
            path=path,
        )

    def _default_major_prompt(self) -> str:
        return """You are a security expert. Classify the code into one of these vulnerability categories.

## Categories: {candidates}

## Evidence:
{evidence}

## Code:
```
{code}
```

## Output (JSON):
{{
  "predictions": [
    {{"category": "Memory", "confidence": 0.85, "reason": "..."}},
    {{"category": "Benign", "confidence": 0.10, "reason": "..."}}
  ]
}}"""

    def _default_middle_prompt(self, major: str) -> str:
        return f"""You are a {major} vulnerability expert. Classify the code into a specific subcategory.

## Categories: {{candidates}}

## Evidence:
{{evidence}}

## Code:
```
{{code}}
```

## Output (JSON):
{{{{
  "predictions": [
    {{{{"category": "...", "confidence": 0.85, "reason": "..."}}}}
  ]
}}}}"""

    def _default_cwe_prompt(self, middle: str) -> str:
        return f"""You are a {middle} vulnerability expert. Identify the specific CWE.

## Possible CWEs: {{candidates}}

## Evidence:
{{evidence}}

## Code:
```
{{code}}
```

## Output (JSON):
{{{{
  "predictions": [
    {{{{"cwe": "CWE-XXX", "confidence": 0.85, "reason": "..."}}}}
  ]
}}}}"""
