"""Training data sampler for hierarchical detector.

Implements 1:1:1 sampling strategy:
- Target category samples
- Other vulnerability samples
- Benign samples
"""

import json
import random
from typing import Dict, List, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass

from .hierarchical_detector import (
    MAJOR_TO_MIDDLE, MIDDLE_TO_CWE, CWE_TO_MIDDLE, MIDDLE_TO_MAJOR
)


@dataclass
class TrainingSample:
    """A training sample with label."""
    code: str
    label: str  # "target", "other_vul", "benign"
    cwe: str
    middle: str
    major: str
    description: str = ""


class HierarchicalSampler:
    """Sampler for hierarchical detector training."""

    def __init__(self, data_path: str, seed: int = 42):
        self.seed = seed
        random.seed(seed)

        # Load and organize data
        self.by_major = defaultdict(list)
        self.by_middle = defaultdict(list)
        self.by_cwe = defaultdict(list)
        self.benign = []

        self._load_data(data_path)

    def _load_data(self, path: str):
        """Load JSONL data and organize by category."""
        from ..data.cwe_hierarchy import cwe_to_major, cwe_to_middle

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue

                code = item.get("func", "")
                if len(code) < 50 or len(code) > 5000:
                    continue

                target = int(item.get("target", 0))

                if target == 0:
                    self.benign.append({
                        "code": code,
                        "cwe": "Benign",
                        "middle": "Benign",
                        "major": "Benign",
                        "description": "",
                    })
                else:
                    cwe_codes = item.get("cwe", [])
                    if isinstance(cwe_codes, str):
                        cwe_codes = [cwe_codes] if cwe_codes else []
                    if not cwe_codes:
                        continue

                    cwe = cwe_codes[0]
                    middle = cwe_to_middle(cwe_codes)
                    major = cwe_to_major(cwe_codes)

                    sample = {
                        "code": code,
                        "cwe": cwe,
                        "middle": middle,
                        "major": major,
                        "description": item.get("cve_desc", "")[:300],
                    }

                    self.by_major[major].append(sample)
                    self.by_middle[middle].append(sample)
                    self.by_cwe[cwe].append(sample)

        print(f"📊 Loaded data:")
        print(f"   Benign: {len(self.benign)}")
        print(f"   Majors: {[(k, len(v)) for k, v in self.by_major.items()]}")

    def sample_for_major(self, target_major: str, n_per_class: int = 100) -> List[TrainingSample]:
        """Sample 1:1:1 data for major category detector.

        Returns:
            List of TrainingSample with labels: "target", "other_vul", "benign"
        """
        samples = []

        # Target samples
        target_pool = self.by_major.get(target_major, [])
        n_target = min(n_per_class, len(target_pool))
        for s in random.sample(target_pool, n_target):
            samples.append(TrainingSample(
                code=s["code"], label="target",
                cwe=s["cwe"], middle=s["middle"], major=s["major"],
                description=s["description"],
            ))

        # Other vulnerability samples
        other_pool = []
        for major, pool in self.by_major.items():
            if major != target_major:
                other_pool.extend(pool)
        n_other = min(n_per_class, len(other_pool))
        for s in random.sample(other_pool, n_other):
            samples.append(TrainingSample(
                code=s["code"], label="other_vul",
                cwe=s["cwe"], middle=s["middle"], major=s["major"],
                description=s["description"],
            ))

        # Benign samples
        n_benign = min(n_per_class, len(self.benign))
        for s in random.sample(self.benign, n_benign):
            samples.append(TrainingSample(
                code=s["code"], label="benign",
                cwe="Benign", middle="Benign", major="Benign",
            ))

        random.shuffle(samples)
        return samples

    def sample_for_middle(self, target_middle: str, n_per_class: int = 100) -> List[TrainingSample]:
        """Sample 1:1:1 data for middle category detector."""
        samples = []

        # Target samples
        target_pool = self.by_middle.get(target_middle, [])
        n_target = min(n_per_class, len(target_pool))
        for s in random.sample(target_pool, n_target):
            samples.append(TrainingSample(
                code=s["code"], label="target",
                cwe=s["cwe"], middle=s["middle"], major=s["major"],
                description=s["description"],
            ))

        # Other vulnerability samples (same major, different middle)
        target_major = MIDDLE_TO_MAJOR.get(target_middle, "Logic")
        other_pool = []
        for middle in MAJOR_TO_MIDDLE.get(target_major, []):
            if middle != target_middle:
                other_pool.extend(self.by_middle.get(middle, []))
        # Also add some from other majors
        for major, middles in MAJOR_TO_MIDDLE.items():
            if major != target_major:
                for middle in middles:
                    other_pool.extend(self.by_middle.get(middle, [])[:20])

        n_other = min(n_per_class, len(other_pool))
        if n_other > 0:
            for s in random.sample(other_pool, n_other):
                samples.append(TrainingSample(
                    code=s["code"], label="other_vul",
                    cwe=s["cwe"], middle=s["middle"], major=s["major"],
                    description=s["description"],
                ))

        # Benign samples
        n_benign = min(n_per_class, len(self.benign))
        for s in random.sample(self.benign, n_benign):
            samples.append(TrainingSample(
                code=s["code"], label="benign",
                cwe="Benign", middle="Benign", major="Benign",
            ))

        random.shuffle(samples)
        return samples

    def sample_for_cwe(self, target_cwe: str, n_per_class: int = 50) -> List[TrainingSample]:
        """Sample 1:1:1 data for CWE detector."""
        samples = []

        # Target samples
        target_pool = self.by_cwe.get(target_cwe, [])
        n_target = min(n_per_class, len(target_pool))
        for s in random.sample(target_pool, n_target):
            samples.append(TrainingSample(
                code=s["code"], label="target",
                cwe=s["cwe"], middle=s["middle"], major=s["major"],
                description=s["description"],
            ))

        # Other vulnerability samples (same middle, different CWE)
        target_middle = CWE_TO_MIDDLE.get(target_cwe, "Other")
        other_pool = []
        for cwe in MIDDLE_TO_CWE.get(target_middle, []):
            if cwe != target_cwe:
                other_pool.extend(self.by_cwe.get(cwe, []))
        # Also add some from other middles
        for middle, cwes in MIDDLE_TO_CWE.items():
            if middle != target_middle:
                for cwe in cwes:
                    other_pool.extend(self.by_cwe.get(cwe, [])[:10])

        n_other = min(n_per_class, len(other_pool))
        if n_other > 0:
            for s in random.sample(other_pool, n_other):
                samples.append(TrainingSample(
                    code=s["code"], label="other_vul",
                    cwe=s["cwe"], middle=s["middle"], major=s["major"],
                    description=s["description"],
                ))

        # Benign samples
        n_benign = min(n_per_class, len(self.benign))
        for s in random.sample(self.benign, n_benign):
            samples.append(TrainingSample(
                code=s["code"], label="benign",
                cwe="Benign", middle="Benign", major="Benign",
            ))

        random.shuffle(samples)
        return samples

    def get_all_majors(self) -> List[str]:
        """Get all major categories with samples."""
        return [m for m in MAJOR_TO_MIDDLE.keys() if self.by_major.get(m)]

    def get_all_middles(self) -> List[str]:
        """Get all middle categories with samples."""
        return [m for m in MIDDLE_TO_CWE.keys() if self.by_middle.get(m)]

    def get_all_cwes(self, min_samples: int = 50) -> List[str]:
        """Get all CWEs with >= min_samples samples."""
        return [c for c in self.by_cwe.keys() if len(self.by_cwe[c]) >= min_samples]

    def get_cwe_sample_count(self, cwe: str) -> int:
        """Get sample count for a CWE."""
        return len(self.by_cwe.get(cwe, []))
