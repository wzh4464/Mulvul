#!/usr/bin/env python3
"""Recover the CWD hierarchical experiment from the 0%-accuracy failure mode.

This script is designed to be runnable from the writable repository checkout
while consuming the CWD worktree assets in:

    /Users/zihanwu/.config/superpowers/worktrees/Mulvul/analyze-cwe-cwd-migration

It does four things:
1. Diagnose the historical 0% run by checking prompt/runtime contract mismatch.
2. Build a balanced 50-100 sample evaluation subset with major/middle/CWD coverage.
3. Create a mainline-compatible PromptBundle whose prompts follow ``ranking_v2``.
4. Run either:
   - an offline oracle smoke test to verify Major -> Middle -> CWD routing, or
   - a live OpenRouter evaluation when network access is available.

The current sandbox blocks outbound OpenRouter traffic, so the offline smoke test
is the default mode for local validation in this environment.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import statistics
import sys
import textwrap
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = Path(os.getenv("CWD_RECOVERY_MULVUL_SRC", str(REPO_ROOT / "src"))).resolve()
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from mulvul.mainline.ablations import AblationConfig
from mulvul.mainline.bundle import (
    BundleDefaults,
    NodeSpec,
    PromptBundle,
    TaxonomyGraph,
    TaxonomyNode,
)
from mulvul.mainline.system import MainlineDetectorSystem


DEFAULT_WORKTREE = Path(
    "/Users/zihanwu/.config/superpowers/worktrees/Mulvul/analyze-cwe-cwd-migration"
)
DEFAULT_DATASET = DEFAULT_WORKTREE / "cwd_native_dataset.json"
DEFAULT_HIERARCHY = DEFAULT_WORKTREE / "cwd_hierarchy.json"
DEFAULT_REPAIRED_SCRIPT = DEFAULT_WORKTREE / "cwd_evolution_repaired.py"
DEFAULT_FLAT_RESULTS = DEFAULT_WORKTREE / "cwd_detection_results.json"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "outputs" / "cwd_hierarchical_recovery"

MAJOR_DESCRIPTIONS = {
    "Memory": "Allocation, bounds, pointer lifetime, pointer arithmetic, or memory ownership defects.",
    "Injection": "Untrusted data reaches an interpreter, parser, command channel, or executable context.",
    "Logic": "Incorrect control flow, state handling, or business-security decisions.",
    "Input": "Insufficient validation, sanitization, normalization, or parsing of attacker-controlled input.",
    "Crypto": "Weak cryptographic design, random generation, or secret handling.",
    "Resource": "Leaked or mismanaged resources, handles, locks, or capacity usage.",
    "Other": "Security-relevant weakness that does not fit the higher-level families above.",
    "Benign": "No actionable security weakness is present in the provided code snippet.",
}

MIDDLE_DESCRIPTIONS = {
    "Memory Management": "Unsafe allocation size, allocation arithmetic, initialization, or release behavior.",
    "Buffer Errors": "Out-of-bounds read/write, buffer sizing, or array boundary handling.",
    "Pointer Issues": "Null, dangling, invalid, or otherwise unsafe pointer usage.",
    "Code Injection": "Executable content or code-like payload reaches a dangerous interpreter or sink.",
    "Data Injection": "Attacker-controlled data is injected into structured data channels or downstream consumers.",
    "Resource Leaks": "Memory, handles, or similar resources are leaked or not released correctly.",
}

RANKING_CONTRACT = textwrap.dedent(
    """\
    Return JSON only. Do not add Markdown fences.
    Use this exact schema:
    {
      "predictions": [
        {"category": "<label>", "confidence": 0.82},
        {"category": "<label>", "confidence": 0.14},
        {"category": "<label>", "confidence": 0.04}
      ]
    }

    Rules:
    - Use only labels from ALLOWED_LABELS.
    - Rank labels from most likely to least likely.
    - Confidence must be a float in [0.0, 1.0].
    - If the code is safe or the target family is unsupported, rank "Benign" first.
    - Prefer a concrete vulnerability label over "Benign" when the snippet clearly contains a vulnerability pattern even if imports or surrounding code are incomplete.
    """
)


@dataclass
class SampleRecord:
    sample_id: str
    code: str
    target: str
    major: str
    middle: str | None
    cwd: str | None
    language: str
    source_id: str
    kind: str


@dataclass
class PredictionRecord:
    sample_id: str
    target: str
    expected_major: str
    expected_middle: str | None
    expected_cwd: str | None
    predicted_label: str
    predicted_major: str
    predicted_middle: str | None
    predicted_cwd: str | None
    exact_match: bool
    major_match: bool
    middle_match: bool
    binary_match: bool
    score: float
    path_depth: int
    stage_status: dict[str, Any]


class HistoricalBenchmarkError(RuntimeError):
    """Raised when a historical benchmark file is malformed."""


def stable_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def canonicalize_code(text: str) -> str:
    return (
        textwrap.dedent(text)
        .strip()
        .replace("\r\n", "\n")
        .replace("{{", "{")
        .replace("}}", "}")
    )


def prompt_code_key(text: str) -> str:
    normalized = canonicalize_code(text)[:4000]
    fingerprint = f"{len(normalized)}::{normalized[:2000]}::{normalized[-600:]}"
    return stable_hash(fingerprint)


class CWDExperimentAssets:
    """Load dataset, hierarchy, and historical benchmark metadata."""

    def __init__(
        self,
        dataset_path: Path,
        hierarchy_path: Path,
        repaired_script_path: Path,
        flat_results_path: Path | None = None,
    ):
        self.dataset_path = dataset_path
        self.hierarchy_path = hierarchy_path
        self.repaired_script_path = repaired_script_path
        self.flat_results_path = flat_results_path

        self.dataset = self._load_json(dataset_path)
        self.hierarchy = self._load_json(hierarchy_path)
        self.repaired_source = repaired_script_path.read_text(encoding="utf-8")
        self.flat_results = (
            self._load_json(flat_results_path) if flat_results_path and flat_results_path.exists() else None
        )

        self.major_to_middle = self.hierarchy["MAJOR_TO_MIDDLE"]
        self.middle_to_cwd = self.hierarchy["MIDDLE_TO_CWD"]
        self.cwd_to_middle = {
            cwd_id: middle
            for middle, cwd_ids in self.middle_to_cwd.items()
            for cwd_id in cwd_ids
        }
        self.middle_to_major = {
            middle: major
            for major, middles in self.major_to_middle.items()
            for middle in middles
        }
        self.cwd_info = self._build_cwd_info()

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        return json.loads(path.read_text(encoding="utf-8"))

    def _build_cwd_info(self) -> dict[str, dict[str, str]]:
        info: dict[str, dict[str, str]] = {}
        for example in self.dataset.get("examples", []):
            labels = example.get("labels", {})
            cwd_id = labels.get("cwd_id")
            if not cwd_id or cwd_id in info:
                continue
            info[cwd_id] = {
                "name": labels.get("cwd_name") or cwd_id,
                "description": labels.get("cwd_description") or "",
            }
        return info

    def resolve_label_path(self, cwd_id: str | None) -> tuple[str, str | None, str | None]:
        if not cwd_id:
            return "Benign", None, None
        middle = self.cwd_to_middle.get(cwd_id)
        major = self.middle_to_major.get(middle) if middle else None
        return major or "Other", middle, cwd_id

    def iter_vulnerable_samples(self) -> list[SampleRecord]:
        samples: list[SampleRecord] = []
        for example in self.dataset.get("examples", []):
            labels = example.get("labels", {})
            cwd_id = labels.get("cwd_id")
            code = example.get("code", {})
            vulnerable = (code.get("vulnerable") or "").strip()
            context = (code.get("context") or "").strip()
            if not cwd_id or not vulnerable:
                continue

            major, middle, cwd = self.resolve_label_path(cwd_id)
            full_code = "\n".join(part for part in (context, vulnerable) if part).strip()
            samples.append(
                SampleRecord(
                    sample_id=str(example.get("id")),
                    code=full_code,
                    target="Vulnerable",
                    major=major,
                    middle=middle,
                    cwd=cwd,
                    language=labels.get("language") or "unknown",
                    source_id=str(example.get("id")),
                    kind="vulnerable",
                )
            )
        return samples

    def iter_benign_samples(self) -> list[SampleRecord]:
        samples: list[SampleRecord] = []
        for example in self.dataset.get("examples", []):
            labels = example.get("labels", {})
            code = example.get("code", {})
            benign = (code.get("benign") or "").strip()
            context = (code.get("context") or "").strip()
            if not benign:
                continue
            full_code = "\n".join(part for part in (context, benign) if part).strip()
            samples.append(
                SampleRecord(
                    sample_id=f"{example.get('id')}_benign",
                    code=full_code,
                    target="Benign",
                    major="Benign",
                    middle=None,
                    cwd=None,
                    language=labels.get("language") or "unknown",
                    source_id=str(example.get("id")),
                    kind="benign",
                )
            )
        return samples

    def diagnose_zero_accuracy(self) -> dict[str, Any]:
        """Summarize root causes visible from the repaired script and runtime contract."""
        causes: list[dict[str, str]] = []
        historical_context: dict[str, Any] = {}

        if '回答"VULNERABLE"' in self.repaired_source and '"predictions"' not in self.repaired_source:
            causes.append(
                {
                    "category": "prompt_contract_mismatch",
                    "severity": "critical",
                    "evidence": (
                        "Node prompts ask for plain VULNERABLE/BENIGN text, but the mainline scorer only trusts "
                        "ranking_v2 JSON predictions."
                    ),
                    "impact": "Major nodes abstain, no route is accepted, and the detector falls back to Benign.",
                }
            )

        if "BundleDefaults(default_threshold=0.5)" in self.repaired_source:
            causes.append(
                {
                    "category": "over_conservative_threshold",
                    "severity": "high",
                    "evidence": "The bundle keeps the default 0.5 threshold for every stage.",
                    "impact": "Moderate-confidence vulnerable rankings are discarded before the cascade can continue.",
                }
            )

        if "train_samples[:8]" in self.repaired_source:
            causes.append(
                {
                    "category": "biased_eval_slice",
                    "severity": "medium",
                    "evidence": "Evaluation only uses the first 8 converted vulnerable samples from the dataset.",
                    "impact": "The run is not balanced, does not include benign examples, and cannot characterize the hierarchy.",
                }
            )

        if "/Users/zihanwu/Public/codes/Mulvul/src" in self.repaired_source:
            causes.append(
                {
                    "category": "cross_checkout_import",
                    "severity": "medium",
                    "evidence": "The script hard-codes another checkout's src directory instead of using the current worktree.",
                    "impact": "Experiment code and runtime version can drift, making debugging and reproduction unreliable.",
                }
            )

        if self.flat_results:
            flat_accuracy = float(self.flat_results["summary"]["accuracy"])
            flat_samples = int(self.flat_results["summary"]["total_samples"])
            causes.append(
                {
                    "category": "historical_control",
                    "severity": "supporting",
                    "evidence": (
                        "The historical flat CWD detector reached "
                        f"{flat_accuracy:.1%} accuracy on {flat_samples} samples."
                    ),
                    "impact": "This confirms the 0% result is a pipeline bug, not an inherent inability to detect CWD vulnerabilities.",
                }
            )
            historical_context["flat_cwd_vs_mulvul_baseline"] = {
                "flat_accuracy": flat_accuracy,
                "flat_samples": flat_samples,
                "mulvul_baseline_accuracy": 0.227,
                "p_value_exact_binomial": exact_binomial_test(
                    round(flat_accuracy * flat_samples),
                    flat_samples,
                    0.227,
                ),
                "note": "Historical flat-CWD result is significantly above the published 22.7% Mulvul baseline under a one-sample exact binomial test.",
            }

        return {
            "dataset_path": str(self.dataset_path),
            "hierarchy_path": str(self.hierarchy_path),
            "repaired_script_path": str(self.repaired_script_path),
            "historical_flat_results_path": str(self.flat_results_path) if self.flat_results_path else None,
            "root_causes": causes,
            "historical_context": historical_context,
        }


class BalancedSubsetBuilder:
    """Create a balanced vulnerable+benign subset with hierarchy coverage."""

    def __init__(self, assets: CWDExperimentAssets, rng: random.Random):
        self.assets = assets
        self.rng = rng

    def build(
        self,
        total_samples: int,
        benign_ratio: float,
        max_per_cwd: int,
    ) -> list[SampleRecord]:
        vulnerable_target = max(1, round(total_samples * (1.0 - benign_ratio)))
        benign_target = max(1, total_samples - vulnerable_target)

        vuln_by_cwd: dict[str, list[SampleRecord]] = defaultdict(list)
        for sample in self.assets.iter_vulnerable_samples():
            if sample.cwd is not None:
                vuln_by_cwd[sample.cwd].append(sample)
        for samples in vuln_by_cwd.values():
            self.rng.shuffle(samples)

        selected_vuln: list[SampleRecord] = []
        per_cwd = Counter()
        per_middle = Counter()
        per_major = Counter()

        # Coverage pass: at least one sample per available CWD if possible.
        for cwd_id in sorted(vuln_by_cwd):
            if len(selected_vuln) >= vulnerable_target:
                break
            sample = vuln_by_cwd[cwd_id].pop()
            selected_vuln.append(sample)
            per_cwd[cwd_id] += 1
            if sample.middle:
                per_middle[sample.middle] += 1
            per_major[sample.major] += 1

        # Top-up pass: prefer underrepresented majors/middles/CWDs.
        while len(selected_vuln) < vulnerable_target:
            candidate = self._pick_top_up_candidate(
                vuln_by_cwd=vuln_by_cwd,
                per_cwd=per_cwd,
                per_middle=per_middle,
                per_major=per_major,
                max_per_cwd=max_per_cwd,
            )
            if candidate is None:
                break
            selected_vuln.append(candidate)
            per_cwd[candidate.cwd] += 1  # type: ignore[index]
            if candidate.middle:
                per_middle[candidate.middle] += 1
            per_major[candidate.major] += 1

        benign_pool = self.assets.iter_benign_samples()
        self.rng.shuffle(benign_pool)
        selected_benign = benign_pool[:benign_target]

        combined = selected_vuln + selected_benign
        self.rng.shuffle(combined)
        return combined

    def _pick_top_up_candidate(
        self,
        *,
        vuln_by_cwd: dict[str, list[SampleRecord]],
        per_cwd: Counter,
        per_middle: Counter,
        per_major: Counter,
        max_per_cwd: int,
    ) -> SampleRecord | None:
        scored: list[tuple[tuple[int, int, int, int, float], str]] = []
        for cwd_id, remaining in vuln_by_cwd.items():
            if not remaining or per_cwd[cwd_id] >= max_per_cwd:
                continue
            probe = remaining[-1]
            middle_count = per_middle[probe.middle] if probe.middle else 999999
            major_count = per_major[probe.major]
            scored.append(
                (
                    (
                        major_count,
                        middle_count,
                        per_cwd[cwd_id],
                        len(remaining) * -1,
                        self.rng.random(),
                    ),
                    cwd_id,
                )
            )
        if not scored:
            return None
        scored.sort(key=lambda item: item[0])
        chosen_cwd = scored[0][1]
        return vuln_by_cwd[chosen_cwd].pop()


class CWDPromptBundleFactory:
    """Create a CWD PromptBundle that matches the mainline ``ranking_v2`` scorer."""

    def __init__(self, assets: CWDExperimentAssets):
        self.assets = assets

    def create_bundle(self) -> PromptBundle:
        nodes: dict[str, NodeSpec] = {}
        taxonomy_nodes: dict[str, TaxonomyNode] = {}

        major_labels = list(self.assets.major_to_middle.keys())
        major_candidates = major_labels + ["Benign"]
        major_block = self._candidate_block("major", major_candidates)

        for major in major_labels:
            node_id = self._major_node_id(major)
            taxonomy_nodes[node_id] = TaxonomyNode(
                node_id=node_id,
                stage="major",
                label=major,
                display_name=major,
                parent_id=None,
            )
            nodes[node_id] = NodeSpec(
                node_id=node_id,
                stage="major",
                target_label=major,
                threshold=0.34,
                instruction_template=self._major_prompt(major, major_block),
                metadata={"stage_family": "cwd_major"},
            )

        benign_node_id = self._major_node_id("Benign")
        taxonomy_nodes[benign_node_id] = TaxonomyNode(
            node_id=benign_node_id,
            stage="major",
            label="Benign",
            display_name="Benign",
            parent_id=None,
        )
        nodes[benign_node_id] = NodeSpec(
            node_id=benign_node_id,
            stage="major",
            target_label="Benign",
            threshold=0.42,
            instruction_template=self._major_prompt("Benign", major_block),
            metadata={"stage_family": "cwd_major"},
        )

        for major, middles in self.assets.major_to_middle.items():
            available_middles = [middle for middle in middles if middle in self.assets.middle_to_cwd]
            if not available_middles:
                continue
            middle_candidates = available_middles + ["Benign"]
            middle_block = self._candidate_block("middle", middle_candidates)

            for middle in available_middles:
                node_id = self._middle_node_id(middle)
                taxonomy_nodes[node_id] = TaxonomyNode(
                    node_id=node_id,
                    stage="middle",
                    label=middle,
                    display_name=middle,
                    parent_id=self._major_node_id(major),
                )
                nodes[node_id] = NodeSpec(
                    node_id=node_id,
                    stage="middle",
                    target_label=middle,
                    threshold=0.30,
                    instruction_template=self._middle_prompt(middle, middle_block),
                    metadata={"stage_family": "cwd_middle", "parent_major": major},
                )

        for middle, cwd_ids in self.assets.middle_to_cwd.items():
            cwe_candidates = list(cwd_ids) + ["Benign"]
            cwe_block = self._candidate_block("cwe", cwe_candidates)
            for cwd_id in cwd_ids:
                node_id = self._cwd_node_id(cwd_id)
                taxonomy_nodes[node_id] = TaxonomyNode(
                    node_id=node_id,
                    stage="cwe",
                    label=cwd_id,
                    display_name=cwd_id,
                    parent_id=self._middle_node_id(middle),
                )
                nodes[node_id] = NodeSpec(
                    node_id=node_id,
                    stage="cwe",
                    target_label=cwd_id,
                    threshold=0.27,
                    instruction_template=self._cwd_prompt(cwd_id, cwe_block),
                    metadata={"stage_family": "cwd_leaf", "parent_middle": middle},
                )

        bundle = PromptBundle(
            schema_version="2",
            taxonomy=TaxonomyGraph(
                version="cwd-hierarchical-recovery-1.0",
                stage_order=("major", "middle", "cwe"),
                nodes=taxonomy_nodes,
                benign_label="Benign",
            ),
            nodes=nodes,
            defaults=BundleDefaults(
                default_threshold=0.34,
                distrust_fallback=False,
                policy_name="greedy",
                policy_config={"major_top_k": 1, "middle_top_k": 1},
            ),
            training_metadata={
                "experiment": "cwd_hierarchical_recovery",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "node_count": len(nodes),
            },
            data_fingerprint=f"cwd-{stable_hash(str(self.assets.dataset_path))[:12]}",
            code_revision="cwd-hierarchical-recovery-v1",
        )
        errors = bundle.validate(allow_partial=True)
        if errors:
            raise ValueError(f"Bundle validation failed: {errors}")
        return bundle

    def _major_prompt(self, target_label: str, candidate_block: str) -> str:
        return textwrap.dedent(
            f"""\
            STAGE: major
            TARGET_LABEL: {target_label}
            ALLOWED_LABELS: {{candidates}}

            Task:
            Decide the best high-level vulnerability family for the code. Focus on actionable security behavior, not compilation quality.

            Candidate guidance:
            {candidate_block}

            CODE_BEGIN
            {{code}}
            CODE_END

            {RANKING_CONTRACT}
            """
        )

    def _middle_prompt(self, target_label: str, candidate_block: str) -> str:
        return textwrap.dedent(
            f"""\
            STAGE: middle
            TARGET_LABEL: {target_label}
            PARENT_MAJOR: {{parent_label}}
            ALLOWED_LABELS: {{candidates}}

            Task:
            The parent major family has already been accepted. Choose the best middle-stage subtype within that family.

            Candidate guidance:
            {candidate_block}

            CODE_BEGIN
            {{code}}
            CODE_END

            {RANKING_CONTRACT}
            """
        )

    def _cwd_prompt(self, target_label: str, candidate_block: str) -> str:
        return textwrap.dedent(
            f"""\
            STAGE: cwe
            TARGET_LABEL: {target_label}
            PARENT_MIDDLE: {{parent_label}}
            ALLOWED_LABELS: {{candidates}}

            Task:
            Choose the most likely concrete CWD identifier for the vulnerability pattern. Distinguish similar labels carefully.

            Candidate guidance:
            {candidate_block}

            CODE_BEGIN
            {{code}}
            CODE_END

            {RANKING_CONTRACT}
            """
        )

    def _candidate_block(self, stage: str, labels: Iterable[str]) -> str:
        lines: list[str] = []
        for label in labels:
            if stage == "major":
                desc = MAJOR_DESCRIPTIONS.get(label, label)
            elif stage == "middle":
                desc = MIDDLE_DESCRIPTIONS.get(label, label)
            elif label == "Benign":
                desc = MAJOR_DESCRIPTIONS["Benign"]
            else:
                cwd_info = self.assets.cwd_info.get(label, {})
                name = cwd_info.get("name", "")
                description = cwd_info.get("description", "")
                summary = (description or name or label).replace("\n", " ").strip()
                summary = re.sub(r"\s+", " ", summary)
                desc = f"{name} | {summary[:140]}".strip(" |")
            lines.append(f"- {label}: {desc}")
        return "\n".join(lines)

    @staticmethod
    def _major_node_id(label: str) -> str:
        return f"major_{label.lower()}"

    @staticmethod
    def _middle_node_id(label: str) -> str:
        return f"middle_{label.lower().replace(' ', '_')}"

    @staticmethod
    def _cwd_node_id(label: str) -> str:
        return f"cwd_{label.lower().replace('-', '_')}"


class OracleClient:
    """Offline client that returns perfect ranking_v2 JSON for smoke tests."""

    def __init__(self, truth_by_hash: dict[str, SampleRecord], samples: list[SampleRecord]):
        self.truth_by_hash = truth_by_hash
        self.samples = samples

    def generate(self, prompt: str, **_: Any) -> str:
        stage_match = re.search(r"STAGE:\s*(major|middle|cwe)", prompt)
        allowed_match = re.search(r"ALLOWED_LABELS:\s*(.+)", prompt)
        code_match = re.search(r"CODE_BEGIN\s*\n(.*?)\n\s*CODE_END", prompt, re.DOTALL)
        stage = stage_match.group(1) if stage_match else "major"
        allowed = self._parse_allowed_labels(allowed_match.group(1) if allowed_match else "")
        code = code_match.group(1) if code_match else ""
        code_key = prompt_code_key(code)
        sample = self.truth_by_hash.get(code_key) or self._find_by_prefix(code)
        if sample is None:
            raise KeyError(
                f"OracleClient could not recover CODE_BEGIN/CODE_END payload from prompt. "
                f"Prompt prefix: {prompt[:240]!r}"
            )

        if sample.target == "Benign":
            choice = "Benign"
        elif stage == "major":
            choice = sample.major
        elif stage == "middle":
            choice = sample.middle or "Benign"
        else:
            choice = sample.cwd or "Benign"

        if choice not in allowed:
            choice = "Benign" if "Benign" in allowed else allowed[0]

        alternatives = [label for label in allowed if label != choice]
        predictions = [{"category": choice, "confidence": 0.97}]
        if alternatives:
            predictions.append({"category": alternatives[0], "confidence": 0.02})
        if len(alternatives) > 1:
            predictions.append({"category": alternatives[1], "confidence": 0.01})
        return json.dumps({"predictions": predictions}, ensure_ascii=False)

    @staticmethod
    def _parse_allowed_labels(raw: str) -> list[str]:
        if "|" in raw:
            return [piece.strip() for piece in raw.split("|") if piece.strip()]
        return [piece.strip() for piece in raw.split(",") if piece.strip()]

    def _find_by_prefix(self, prompt_code: str) -> SampleRecord | None:
        excerpt = canonicalize_code(prompt_code)
        matches = [
            sample
            for sample in self.samples
            if canonicalize_code(sample.code).startswith(excerpt)
        ]
        if not matches:
            return None
        matches.sort(key=lambda sample: len(canonicalize_code(sample.code)))
        return matches[0]


class FixedGenerationClient:
    """Inject stable generation kwargs into the runtime scorer."""

    def __init__(self, base_client: Any, *, temperature: float, max_tokens: int):
        self.base_client = base_client
        self.temperature = temperature
        self.max_tokens = max_tokens

    def generate(self, prompt: str, **kwargs: Any) -> str:
        merged = dict(kwargs)
        merged.setdefault("temperature", self.temperature)
        merged.setdefault("max_tokens", self.max_tokens)
        return self.base_client.generate(prompt, **merged)


class ExperimentRunner:
    """Run the recovered hierarchical experiment."""

    def __init__(self, assets: CWDExperimentAssets):
        self.assets = assets

    def evaluate(
        self,
        samples: list[SampleRecord],
        *,
        model_name: str,
        api_base: str,
        temperature: float,
        max_tokens: int,
        use_oracle: bool,
    ) -> tuple[PromptBundle, list[PredictionRecord], dict[str, Any]]:
        bundle = CWDPromptBundleFactory(self.assets).create_bundle()

        if use_oracle:
            truth_map = {prompt_code_key(sample.code): sample for sample in samples}
            llm_client: Any = FixedGenerationClient(
                OracleClient(truth_map, samples),
                temperature=temperature,
                max_tokens=max_tokens,
            )
        else:
            from mulvul.llm.client import OpenAICompatibleClient

            api_key = os.getenv("OPENROUTER_API_KEY")
            if not api_key:
                raise RuntimeError("OPENROUTER_API_KEY is not set for online mode.")
            llm_client = FixedGenerationClient(
                OpenAICompatibleClient(
                    model_name=model_name,
                    api_base=api_base,
                    api_key=api_key,
                ),
                temperature=temperature,
                max_tokens=max_tokens,
            )

        detector = MainlineDetectorSystem(
            llm_client=llm_client,
            artifact=bundle,
            ablations=AblationConfig(use_retrieval=False, parallel_scoring=False),
        )

        predictions: list[PredictionRecord] = []
        timings: list[float] = []

        for sample in samples:
            start = time.time()
            result = detector.detect(sample.code)
            elapsed = time.time() - start
            timings.append(elapsed)
            stage_status = self._stage_status(result)
            predictions.append(
                PredictionRecord(
                    sample_id=sample.sample_id,
                    target=sample.target,
                    expected_major=sample.major,
                    expected_middle=sample.middle,
                    expected_cwd=sample.cwd,
                    predicted_label=result.prediction,
                    predicted_major=result.major,
                    predicted_middle=result.middle,
                    predicted_cwd=result.cwe,
                    exact_match=result.cwe == sample.cwd if sample.target == "Vulnerable" else result.prediction == "Benign",
                    major_match=result.major == sample.major,
                    middle_match=result.middle == sample.middle,
                    binary_match=result.is_vulnerable == (sample.target == "Vulnerable"),
                    score=result.score,
                    path_depth=len([label for label in (result.major, result.middle, result.cwe) if label]),
                    stage_status=stage_status,
                )
            )

        metrics = self._compute_metrics(samples, predictions, timings)
        return bundle, predictions, metrics

    @staticmethod
    def _stage_status(result: Any) -> dict[str, Any]:
        stage_status: dict[str, Any] = {}
        for stage, scores in result.stage_scores.items():
            if not scores:
                stage_status[stage] = {"scored": 0, "accepted": 0}
                continue
            accepted = sum(1 for item in scores if item.predicted_label == item.target and item.confidence > 0)
            stage_status[stage] = {
                "scored": len(scores),
                "accepted": accepted,
                "top_target": scores[0].target,
                "top_confidence": scores[0].confidence,
            }
        return stage_status

    def _compute_metrics(
        self,
        samples: list[SampleRecord],
        predictions: list[PredictionRecord],
        timings: list[float],
    ) -> dict[str, Any]:
        vuln_records = [record for record in predictions if record.target == "Vulnerable"]
        benign_records = [record for record in predictions if record.target == "Benign"]
        exact_correct = sum(1 for record in predictions if record.exact_match)
        vulnerable_exact_correct = sum(1 for record in vuln_records if record.exact_match)
        major_correct = sum(1 for record in predictions if record.major_match)
        middle_correct = sum(1 for record in vuln_records if record.middle_match)
        binary_correct = sum(1 for record in predictions if record.binary_match)

        summary = {
            "total_samples": len(predictions),
            "vulnerable_samples": len(vuln_records),
            "benign_samples": len(benign_records),
            "exact_correct": exact_correct,
            "vulnerable_exact_correct": vulnerable_exact_correct,
            "major_correct": major_correct,
            "middle_correct": middle_correct,
            "binary_correct": binary_correct,
            "exact_accuracy": self._safe_mean(record.exact_match for record in predictions),
            "vulnerable_exact_accuracy": self._safe_mean(record.exact_match for record in vuln_records),
            "major_accuracy": self._safe_mean(record.major_match for record in predictions),
            "middle_accuracy": self._safe_mean(record.middle_match for record in vuln_records),
            "binary_accuracy": self._safe_mean(record.binary_match for record in predictions),
            "avg_score": statistics.mean(record.score for record in predictions) if predictions else 0.0,
            "avg_latency_sec": statistics.mean(timings) if timings else 0.0,
        }

        by_major = Counter(sample.major for sample in samples)
        by_middle = Counter(sample.middle for sample in samples if sample.middle)
        by_cwd = Counter(sample.cwd for sample in samples if sample.cwd)
        pred_major = Counter(record.predicted_major for record in predictions)
        pred_middle = Counter(record.predicted_middle for record in predictions if record.predicted_middle)
        pred_cwd = Counter(record.predicted_cwd for record in predictions if record.predicted_cwd)
        depth = Counter(record.path_depth for record in predictions)

        benchmark = self._historical_comparison(
            exact_correct=summary["exact_correct"],
            total_samples=summary["total_samples"],
            vulnerable_exact_correct=summary["vulnerable_exact_correct"],
            vulnerable_samples=summary["vulnerable_samples"],
        )
        return {
            "summary": summary,
            "coverage": {
                "ground_truth_major": dict(by_major),
                "ground_truth_middle": dict(by_middle),
                "ground_truth_cwd": dict(by_cwd),
                "predicted_major": dict(pred_major),
                "predicted_middle": dict(pred_middle),
                "predicted_cwd": dict(pred_cwd),
                "path_depth": dict(depth),
            },
            "significance": benchmark,
        }

    def _historical_comparison(
        self,
        *,
        exact_correct: int,
        total_samples: int,
        vulnerable_exact_correct: int,
        vulnerable_samples: int,
    ) -> dict[str, Any]:
        observed_accuracy = exact_correct / total_samples if total_samples else 0.0
        comparisons: dict[str, Any] = {
            "wilson_ci_95": list(wilson_interval(observed_accuracy, total_samples)),
            "vulnerable_wilson_ci_95": list(
                wilson_interval(
                    vulnerable_exact_correct / vulnerable_samples if vulnerable_samples else 0.0,
                    vulnerable_samples,
                )
            ),
        }
        if total_samples <= 0:
            return comparisons

        if self.assets.flat_results and vulnerable_samples > 0:
            flat_accuracy = float(self.assets.flat_results["summary"]["accuracy"])
            comparisons["vs_historical_flat_cwd"] = {
                "historical_accuracy": flat_accuracy,
                "historical_samples": int(self.assets.flat_results["summary"]["total_samples"]),
                "observed_accuracy": vulnerable_exact_correct / vulnerable_samples,
                "p_value_exact_binomial": exact_binomial_test(
                    vulnerable_exact_correct,
                    vulnerable_samples,
                    flat_accuracy,
                ),
                "note": "One-sample exact binomial test on vulnerable-only exact accuracy against the historical flat-CWD rate because raw paired predictions are unavailable here.",
            }

        mulvul_baseline = 0.227
        comparisons["vs_mulvul_baseline"] = {
            "historical_accuracy": mulvul_baseline,
            "observed_accuracy": observed_accuracy,
            "p_value_exact_binomial": exact_binomial_test(
                exact_correct,
                total_samples,
                mulvul_baseline,
            ),
            "note": "Historical Mulvul v0.2.0 comparison uses the published 22.7% end-to-end rate as a fixed null benchmark. Label mix differs from the balanced subset, so treat this as directional.",
        }
        return comparisons

    @staticmethod
    def _safe_mean(values: Iterable[bool]) -> float:
        values = list(values)
        if not values:
            return 0.0
        return sum(1 for value in values if value) / len(values)


def exact_binomial_test(successes: int, trials: int, p0: float) -> float:
    """Two-sided exact binomial test without scipy."""
    if trials <= 0:
        return 1.0
    pmf_observed = binom_pmf(successes, trials, p0)
    total = 0.0
    for k in range(trials + 1):
        pmf = binom_pmf(k, trials, p0)
        if pmf <= pmf_observed + 1e-15:
            total += pmf
    return min(total, 1.0)


def binom_pmf(successes: int, trials: int, p: float) -> float:
    return math.comb(trials, successes) * (p**successes) * ((1.0 - p) ** (trials - successes))


def wilson_interval(p_hat: float, trials: int, z: float = 1.96) -> tuple[float, float]:
    if trials <= 0:
        return 0.0, 1.0
    denominator = 1.0 + (z**2 / trials)
    center = (p_hat + z**2 / (2 * trials)) / denominator
    margin = z * math.sqrt((p_hat * (1 - p_hat) + z**2 / (4 * trials)) / trials) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def write_markdown_report(
    path: Path,
    *,
    diagnosis: dict[str, Any],
    subset: list[SampleRecord],
    metrics: dict[str, Any],
    mode: str,
) -> None:
    summary = metrics["summary"]
    significance = metrics["significance"]
    coverage = metrics["coverage"]
    lines = [
        "# CWD Hierarchical Recovery Report",
        "",
        f"- Mode: `{mode}`",
        f"- Samples: {summary['total_samples']}",
        f"- Vulnerable / Benign: {summary['vulnerable_samples']} / {summary['benign_samples']}",
        f"- Exact accuracy: {summary['exact_accuracy']:.3f}",
        f"- Vulnerable-only exact accuracy: {summary['vulnerable_exact_accuracy']:.3f}",
        f"- Major accuracy: {summary['major_accuracy']:.3f}",
        f"- Middle accuracy: {summary['middle_accuracy']:.3f}",
        f"- Binary accuracy: {summary['binary_accuracy']:.3f}",
        f"- Average latency: {summary['avg_latency_sec']:.3f}s",
        "",
    ]
    if mode == "offline":
        lines.extend(
            [
                "> Offline mode uses an oracle smoke test client.",
                "> These accuracy numbers validate prompt contract, parsing, and cascade routing only.",
                "> They are not real OpenRouter model performance metrics.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "> Online mode uses the configured OpenRouter model.",
                "> These accuracy numbers are real model evaluation metrics on the saved balanced subset.",
                "",
            ]
        )
    lines.extend(["## Root Causes", ""])
    for item in diagnosis["root_causes"]:
        lines.append(f"- `{item['category']}` ({item['severity']}): {item['evidence']} Impact: {item['impact']}")

    historical_context = diagnosis.get("historical_context", {})
    flat_vs_baseline = historical_context.get("flat_cwd_vs_mulvul_baseline")
    if flat_vs_baseline:
        lines.extend(
            [
                "",
                "## Historical Benchmark Context",
                "",
                (
                    f"- Historical flat CWD {flat_vs_baseline['flat_accuracy']:.3f} vs Mulvul baseline "
                    f"{flat_vs_baseline['mulvul_baseline_accuracy']:.3f}: "
                    f"p={flat_vs_baseline['p_value_exact_binomial']:.4g}. "
                    f"{flat_vs_baseline['note']}"
                ),
            ]
        )

    lines.extend(
        [
            "",
            "## Subset Coverage",
            "",
            f"- Ground-truth majors: {json.dumps(coverage['ground_truth_major'], ensure_ascii=False)}",
            f"- Ground-truth middles: {json.dumps(coverage['ground_truth_middle'], ensure_ascii=False)}",
            f"- Ground-truth CWD count: {len(coverage['ground_truth_cwd'])}",
            f"- Path depth distribution: {json.dumps(coverage['path_depth'], ensure_ascii=False)}",
            "",
            "## Statistical Comparison",
            "",
            f"- Wilson 95% CI: {tuple(round(value, 4) for value in significance['wilson_ci_95'])}",
            f"- Vulnerable-only Wilson 95% CI: {tuple(round(value, 4) for value in significance['vulnerable_wilson_ci_95'])}",
        ]
    )

    flat = significance.get("vs_historical_flat_cwd")
    if flat:
        lines.append(
            f"- Vs historical flat CWD {flat['historical_accuracy']:.3f}: p={flat['p_value_exact_binomial']:.4g}. {flat['note']}"
        )
    mulvul = significance.get("vs_mulvul_baseline")
    if mulvul:
        lines.append(
            f"- Vs Mulvul baseline {mulvul['historical_accuracy']:.3f}: p={mulvul['p_value_exact_binomial']:.4g}. {mulvul['note']}"
        )

    lines.extend(
        [
            "",
            "## Recommendations",
            "",
            "- Keep the mainline runtime unchanged; fix the experiment by aligning prompts to ranking_v2 and lowering overly conservative thresholds.",
            "- Use balanced evaluation subsets. The raw dataset is memory-dominated and can hide routing failures.",
            "- Remove hard-coded cross-checkout imports so the worktree runs against its own source tree.",
            "- When network is available, run the same script in `--mode online` to obtain real accuracy on the saved balanced subset.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--hierarchy", type=Path, default=DEFAULT_HIERARCHY)
    parser.add_argument("--repaired-script", type=Path, default=DEFAULT_REPAIRED_SCRIPT)
    parser.add_argument("--flat-results", type=Path, default=DEFAULT_FLAT_RESULTS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--mode", choices=("offline", "online"), default="offline")
    parser.add_argument("--sample-count", type=int, default=96)
    parser.add_argument("--benign-ratio", type=float, default=0.33)
    parser.add_argument("--max-per-cwd", type=int, default=3)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--model-name", default="anthropic/claude-3.5-sonnet")
    parser.add_argument("--api-base", default="https://openrouter.ai/api/v1")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--max-tokens", type=int, default=600)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    run_dir = args.output_dir / timestamp
    run_dir.mkdir(parents=True, exist_ok=True)

    assets = CWDExperimentAssets(
        dataset_path=args.dataset,
        hierarchy_path=args.hierarchy,
        repaired_script_path=args.repaired_script,
        flat_results_path=args.flat_results,
    )

    diagnosis = assets.diagnose_zero_accuracy()
    rng = random.Random(args.seed)
    subset = BalancedSubsetBuilder(assets, rng).build(
        total_samples=args.sample_count,
        benign_ratio=args.benign_ratio,
        max_per_cwd=args.max_per_cwd,
    )

    bundle, predictions, metrics = ExperimentRunner(assets).evaluate(
        subset,
        model_name=args.model_name,
        api_base=args.api_base,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        use_oracle=(args.mode == "offline"),
    )

    write_json(run_dir / "diagnosis.json", diagnosis)
    write_json(run_dir / "subset.json", [asdict(sample) for sample in subset])
    write_json(run_dir / "bundle.json", bundle.to_dict())
    write_json(run_dir / "predictions.json", [asdict(record) for record in predictions])
    write_json(run_dir / "metrics.json", metrics)
    write_json(
        run_dir / "run_config.json",
        {
            "mode": args.mode,
            "sample_count": args.sample_count,
            "benign_ratio": args.benign_ratio,
            "max_per_cwd": args.max_per_cwd,
            "seed": args.seed,
            "model_name": args.model_name,
            "api_base": args.api_base,
            "temperature": args.temperature,
            "max_tokens": args.max_tokens,
            "dataset": str(args.dataset),
            "hierarchy": str(args.hierarchy),
            "repaired_script": str(args.repaired_script),
        },
    )
    write_markdown_report(
        run_dir / "report.md",
        diagnosis=diagnosis,
        subset=subset,
        metrics=metrics,
        mode=args.mode,
    )

    summary = metrics["summary"]
    print(f"Run directory: {run_dir}")
    print(
        "Summary:",
        json.dumps(
            {
                "mode": args.mode,
                "samples": summary["total_samples"],
                "exact_accuracy": round(summary["exact_accuracy"], 4),
                "major_accuracy": round(summary["major_accuracy"], 4),
                "middle_accuracy": round(summary["middle_accuracy"], 4),
                "binary_accuracy": round(summary["binary_accuracy"], 4),
            },
            ensure_ascii=False,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
