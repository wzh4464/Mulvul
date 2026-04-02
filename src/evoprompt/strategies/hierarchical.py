"""Hierarchical 3-layer CWE classification strategy.

Wraps ThreeLayerDetector to implement the DetectionStrategy protocol.
The detector cascades Layer1 (major) -> Layer2 (middle) -> Layer3 (CWE),
then the strategy maps the result back to the 11-class CWE_MAJOR_CATEGORIES
label space so the evolution loop can score it uniformly.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from evoprompt.data.cwe_categories import CWE_MAJOR_CATEGORIES, map_cwe_to_major
from evoprompt.data.dataset import Sample
from evoprompt.detectors.three_layer_detector import ThreeLayerDetector
from evoprompt.prompts.hierarchical_three_layer import (
    MajorCategory,
    MiddleCategory,
    ThreeLayerPromptFactory,
    ThreeLayerPromptSet,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Map the 3-layer MajorCategory enum to 11-class labels.
# When the detector only reaches Layer 1, we use the major category
# as a coarse proxy.  When it reaches Layer 2 or 3 we can be more specific.
# ---------------------------------------------------------------------------

_MAJOR_TO_11CLASS: Dict[str, str] = {
    "Memory": "Buffer Errors",          # Most common memory issue; refined below
    "Injection": "Injection",
    "Logic": "Concurrency Issues",      # Coarse fallback; refined below
    "Input": "Path Traversal",          # Coarse fallback; refined below
    "Crypto": "Cryptography Issues",
    "Benign": "Benign",
}

_MIDDLE_TO_11CLASS: Dict[str, str] = {
    # Memory sub-categories
    "Buffer Overflow": "Buffer Errors",
    "Use After Free": "Memory Management",
    "NULL Pointer": "Pointer Dereference",
    "Integer Overflow": "Integer Errors",
    "Memory Leak": "Memory Management",
    # Injection sub-categories (all map to Injection)
    "SQL Injection": "Injection",
    "Cross-Site Scripting": "Injection",
    "Command Injection": "Injection",
    "LDAP Injection": "Injection",
    # Logic sub-categories
    "Authentication Bypass": "Other",
    "Race Condition": "Concurrency Issues",
    "Insecure Defaults": "Other",
    # Input sub-categories
    "Path Traversal": "Path Traversal",
    "Input Validation": "Other",
    "Uncontrolled Format String": "Other",
    # Crypto sub-categories
    "Weak Cryptography": "Cryptography Issues",
    "Insecure Randomness": "Cryptography Issues",
    # Benign
    "Safe Code": "Benign",
}


def _map_details_to_label(details: Dict) -> str:
    """Convert ThreeLayerDetector detail dict to an 11-class label.

    Prefers the most specific layer available (layer2 > layer1).
    Falls back through coarser layers if needed.
    """
    # Try Layer 2 (middle category) first -- most discriminative
    layer2 = details.get("layer2")
    if layer2 and layer2 != "Unknown":
        label = _MIDDLE_TO_11CLASS.get(layer2)
        if label:
            return label

    # Fall back to Layer 1 (major category)
    layer1 = details.get("layer1")
    if layer1 and layer1 != "Unknown":
        label = _MAJOR_TO_11CLASS.get(layer1)
        if label:
            return label

    return "Other"


def _cwe_to_label(cwe: Optional[str], details: Dict) -> str:
    """Map a CWE string (e.g. 'CWE-120') to an 11-class label.

    If the CWE is recognized by map_cwe_to_major we use that;
    otherwise we fall back to the layer details.
    """
    if cwe:
        label = map_cwe_to_major([cwe])
        if label != "Other":
            return label

    # CWE not recognized or absent -- use intermediate layers
    return _map_details_to_label(details)


class HierarchicalStrategy:
    """Three-layer hierarchical classification strategy.

    Uses ThreeLayerDetector (Layer1 -> Layer2 -> Layer3) and maps
    the cascade output back to CWE_MAJOR_CATEGORIES (11 classes).
    """

    def __init__(self, llm_client: Any, config: Dict[str, Any] | None = None):
        self.llm_client = llm_client
        self.config = config or {}

        # Build the three-layer prompt set
        prompt_set = self._build_prompt_set()
        use_scale = self.config.get("use_scale_enhancement", False)
        self.detector = ThreeLayerDetector(
            prompt_set=prompt_set,
            llm_client=llm_client,
            use_scale_enhancement=use_scale,
        )

    # ------------------------------------------------------------------
    # DetectionStrategy protocol
    # ------------------------------------------------------------------

    def get_ground_truth(self, sample: Sample) -> str:
        """Return the 11-class ground truth label for *sample*."""
        ground_truth_binary = int(sample.target)
        cwe_codes = sample.metadata.get("cwe", [])
        if ground_truth_binary == 1 and cwe_codes:
            return map_cwe_to_major(cwe_codes)
        return "Benign"

    def predict_batch(
        self, prompt: str, samples: List[Sample], batch_idx: int
    ) -> List[str]:
        """Classify each sample via the 3-layer cascade.

        *prompt* is the Layer-1 prompt currently under evolution.
        We inject it into the detector's prompt_set so the evolution
        loop can optimise it while layers 2/3 stay fixed.
        """
        # Allow the evolution loop to swap in a new Layer-1 prompt
        self.detector.prompt_set.layer1_prompt = prompt

        codes = [s.input_text for s in samples]
        print(f"      [hierarchical] batch predict {len(codes)} samples...")

        predictions: List[str] = []
        for idx, code in enumerate(codes):
            try:
                cwe, details = self.detector.detect(code)
                label = _cwe_to_label(cwe, details)
            except Exception as e:
                logger.warning("Detection failed for sample %d: %s", idx, e)
                label = "Other"

            if batch_idx == 0 and idx < 3:
                cwe_str = cwe or "None"
                layer1 = details.get("layer1", "?") if "details" in dir() else "?"
                layer2 = details.get("layer2", "?") if "details" in dir() else "?"
                print(f"        [debug] sample {idx+1}: L1={layer1} L2={layer2} CWE={cwe_str} -> {label}")

            predictions.append(label)

        return predictions

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_prompt_set(self) -> ThreeLayerPromptSet:
        """Build a ThreeLayerPromptSet, optionally overriding from config."""
        custom = self.config.get("prompt_set")
        if custom and isinstance(custom, dict):
            return ThreeLayerPromptSet.from_dict(custom)

        # Use the factory defaults
        return ThreeLayerPromptFactory.create_default_prompt_set()
