#!/usr/bin/env python3
"""
Optimized CWD cascade experiment built on top of the repaired 49-node taxonomy.

This script keeps the fixed Major -> Middle -> CWD architecture from
`cwd_evolution_repaired.py`, replaces the non-parseable binary prompts with
`ranking_v2` prompts, tunes stage thresholds on a held-out dev set, scales the
evaluation to a diverse 50-100 sample subset, and saves timestamped reports.

When OpenRouter / Anthropic is reachable, the script can run the live LLM
backend. In this sandbox, DNS resolution is unavailable, so the default `auto`
mode falls back to an offline prototype scorer that exercises the exact same
cascade policy and taxonomy.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import math
import os
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

OUTPUT_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = Path("/Users/zihanwu/.config/superpowers/worktrees/Mulvul/analyze-cwe-cwd-migration")
MULVUL_SRC = Path("/Users/zihanwu/Public/codes/Mulvul/src")
if str(SOURCE_ROOT) not in sys.path:
    sys.path.append(str(SOURCE_ROOT))
if str(MULVUL_SRC) not in sys.path:
    sys.path.append(str(MULVUL_SRC))

from cwd_evolution_repaired import CWDPromptBundleFactory
from cwd_hierarchy import (
    get_cwds_for_middle,
    get_hierarchy_path,
    get_major_categories,
    get_middle_categories,
)
from mulvul.llm.client import OpenAICompatibleClient
from mulvul.mainline.bundle import BundleDefaults, NodeScoreResult, PromptBundle
from mulvul.mainline.evaluator import EvaluationSample, MainlineEvaluator
from mulvul.mainline.policy import GreedyCascadePolicy, ScorerContext


DEFAULT_REPORTED_BASELINES = {
    "cwd_flat_reported": 0.447,
    "mulvul_reported": 0.227,
    "zero_accuracy_regression": 0.0,
}

MAJOR_KEYWORDS = {
    "Memory": [
        "strcpy",
        "sprintf",
        "memcpy",
        "memmove",
        "malloc",
        "calloc",
        "realloc",
        "new ",
        "delete",
        "free(",
        "char[",
        "buffer",
        "pointer",
        "nullptr",
        "null",
        "vector<bool>",
    ],
    "Injection": [
        "select ",
        "insert ",
        "update ",
        "delete from",
        "statement",
        "executequery",
        "preparedstatement",
        "runtime.getruntime",
        "processbuilder",
        "system(",
        "exec(",
        "evaluate(",
        "velocityengine",
        "scriptengine",
        "<script",
    ],
    "Resource": [
        "open(",
        "fopen",
        "close(",
        "cjson_print",
        "new ",
        "malloc",
        "delete",
        "free(",
        "release",
        "cleanup",
        "resource",
        "leak",
    ],
}

MIDDLE_KEYWORDS = {
    "Memory Management": [
        "malloc",
        "calloc",
        "realloc",
        "new ",
        "delete",
        "free(",
        "alloc",
        "release",
        "resource",
        "vector<bool>",
        "sizeof",
    ],
    "Buffer Errors": [
        "strcpy",
        "strcat",
        "sprintf",
        "gets(",
        "memcpy",
        "memmove",
        "snprintf",
        "buffer",
        "array",
        "index",
        "out of bounds",
    ],
    "Pointer Issues": [
        "pointer",
        "nullptr",
        "null",
        "->",
        "*",
        "shared_ptr",
        "unique_ptr",
        "return ",
        "&",
    ],
    "Code Injection": [
        "system(",
        "exec(",
        "runtime.getruntime",
        "processbuilder",
        "velocityengine",
        "evaluate(",
        "scriptengine",
        "<script",
    ],
    "Data Injection": [
        "select ",
        "insert ",
        "update ",
        "delete from",
        "statement",
        "executequery",
        "query",
        "jdbc",
        "mybatis",
        "sql",
    ],
    "Resource Leaks": [
        "new ",
        "malloc",
        "open(",
        "cjson_print",
        "close(",
        "free(",
        "delete",
        "release",
        "cleanup",
    ],
}


@dataclass(frozen=True)
class SampleRecord:
    sample_id: str
    source_id: str
    variant: str
    code: str
    final_label: str
    major: str | None
    middle: str | None
    cwe: str | None
    source_cwd: str | None
    language: str
    severity: str | None

    @property
    def is_benign(self) -> bool:
        return self.final_label == "Benign"


@dataclass
class ExperimentConfig:
    eval_samples: int = 80
    dev_samples: int = 48
    vulnerable_ratio: float = 0.75
    min_cwe_vulnerable_samples: int = 6
    seed: int = 13
    backend: str = "auto"
    model_name: str = "gpt-5.4"
    api_base: str = "https://openrouter.ai/api/v1"
    output_root: str = "./cwd_optimized_experiment_results"
    support_top_k: int = 3
    char_ngram_range: tuple[int, int] = (3, 5)
    max_features: int = 60000
    default_major_threshold: float = 0.24
    default_middle_threshold: float = 0.22
    default_cwe_threshold: float = 0.18
    reported_baselines: dict[str, float] | None = None

    def __post_init__(self) -> None:
        if self.reported_baselines is None:
            self.reported_baselines = dict(DEFAULT_REPORTED_BASELINES)


class CWDDataset:
    def __init__(
        self,
        dataset_path: Path,
        *,
        min_cwe_vulnerable_samples: int = 0,
    ):
        with dataset_path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)

        self.dataset_path = dataset_path
        self.min_cwe_vulnerable_samples = max(0, int(min_cwe_vulnerable_samples))
        self.vulnerable_cwe_counts = self._count_vulnerable_examples(raw["examples"])
        self.excluded_cwds = self._select_excluded_cwds(
            raw["cwd_definitions"],
            self.vulnerable_cwe_counts,
        )
        self.active_cwds = sorted(
            cwd_id
            for cwd_id in raw["cwd_definitions"].keys()
            if cwd_id not in self.excluded_cwds
        )
        self.raw = self._filter_raw_dataset(raw)
        self.cwd_definitions = self.raw["cwd_definitions"]
        self.records = self._build_records(self.raw["examples"])
        self.filter_summary = {
            "dataset_path": str(dataset_path),
            "min_cwe_vulnerable_samples": self.min_cwe_vulnerable_samples,
            "excluded_cwds": list(self.excluded_cwds),
            "excluded_cwd_count": len(self.excluded_cwds),
            "active_cwds": list(self.active_cwds),
            "active_cwd_count": len(self.active_cwds),
            "original_example_count": len(raw["examples"]),
            "kept_example_count": len(self.raw["examples"]),
            "removed_example_count": len(raw["examples"]) - len(self.raw["examples"]),
            "vulnerable_cwe_counts": dict(sorted(self.vulnerable_cwe_counts.items())),
        }

    def _count_vulnerable_examples(
        self,
        examples: Sequence[Mapping[str, Any]],
    ) -> dict[str, int]:
        counts: Counter[str] = Counter()
        for example in examples:
            labels = example.get("labels", {})
            code_obj = example.get("code", {})
            cwd_id = labels.get("cwd_id")
            vulnerable = str(code_obj.get("vulnerable", "") or "").strip()
            if cwd_id and vulnerable:
                counts[str(cwd_id)] += 1
        return dict(counts)

    def _select_excluded_cwds(
        self,
        cwd_definitions: Mapping[str, Mapping[str, Any]],
        vulnerable_counts: Mapping[str, int],
    ) -> list[str]:
        if self.min_cwe_vulnerable_samples <= 0:
            return []
        return sorted(
            cwd_id
            for cwd_id in cwd_definitions.keys()
            if vulnerable_counts.get(cwd_id, 0) < self.min_cwe_vulnerable_samples
        )

    @property
    def excluded_by_sample_floor(self) -> list[str]:
        return sorted(
            cwd_id
            for cwd_id in self.excluded_cwds
            if self.vulnerable_cwe_counts.get(cwd_id, 0) < self.min_cwe_vulnerable_samples
        )

    def _filter_raw_dataset(self, raw: Mapping[str, Any]) -> dict[str, Any]:
        if not self.excluded_cwds:
            return {
                "cwd_definitions": dict(raw["cwd_definitions"]),
                "examples": list(raw["examples"]),
            }

        excluded = set(self.excluded_cwds)
        kept_examples = [
            example
            for example in raw["examples"]
            if str(example.get("labels", {}).get("cwd_id") or "") not in excluded
        ]
        kept_definitions = {
            cwd_id: definition
            for cwd_id, definition in raw["cwd_definitions"].items()
            if cwd_id not in excluded
        }
        return {
            "cwd_definitions": kept_definitions,
            "examples": kept_examples,
        }

    def _build_records(self, examples: Sequence[Mapping[str, Any]]) -> list[SampleRecord]:
        records: list[SampleRecord] = []
        for example in examples:
            labels = example.get("labels", {})
            code_obj = example.get("code", {})
            source_id = str(example.get("id"))
            cwd_id = labels.get("cwd_id")
            major, middle, cwe = get_hierarchy_path(cwd_id) if cwd_id else (None, None, None)
            language = str(labels.get("language", "unknown"))
            severity = labels.get("severity")

            vulnerable = str(code_obj.get("vulnerable", "") or "").strip()
            benign = str(code_obj.get("benign", "") or "").strip()
            context = str(code_obj.get("context", "") or "").strip()

            if vulnerable:
                full_code = f"{context}\n{vulnerable}".strip() if context else vulnerable
                records.append(
                    SampleRecord(
                        sample_id=f"{source_id}::vuln",
                        source_id=source_id,
                        variant="vulnerable",
                        code=full_code,
                        final_label=str(cwd_id),
                        major=major,
                        middle=middle,
                        cwe=str(cwd_id),
                        source_cwd=str(cwd_id),
                        language=language,
                        severity=str(severity) if severity is not None else None,
                    )
                )

            if benign:
                full_code = f"{context}\n{benign}".strip() if context else benign
                records.append(
                    SampleRecord(
                        sample_id=f"{source_id}::benign",
                        source_id=source_id,
                        variant="benign",
                        code=full_code,
                        final_label="Benign",
                        major="Benign",
                        middle=None,
                        cwe=None,
                        source_cwd=str(cwd_id) if cwd_id else None,
                        language=language,
                        severity=str(severity) if severity is not None else None,
                    )
                )
        return records

    @property
    def vulnerable_records(self) -> list[SampleRecord]:
        return [record for record in self.records if not record.is_benign]

    @property
    def benign_records(self) -> list[SampleRecord]:
        return [record for record in self.records if record.is_benign]


class OptimizedBundleFactory:
    def __init__(
        self,
        cwd_definitions: Mapping[str, Mapping[str, Any]],
        *,
        active_cwds: Sequence[str] | None = None,
    ):
        self.cwd_definitions = dict(cwd_definitions)
        self.active_cwds = set(active_cwds or cwd_definitions.keys())
        self.excluded_cwds = sorted(
            cwd_id for cwd_id in self.cwd_definitions.keys() if cwd_id not in self.active_cwds
        )

    def build(
        self,
        *,
        major_threshold: float,
        middle_threshold: float,
        cwe_threshold: float,
    ) -> PromptBundle:
        with contextlib.redirect_stdout(io.StringIO()):
            bundle = CWDPromptBundleFactory.create_cwd_bundle()
        bundle = self._prune_bundle(bundle)
        bundle.defaults = BundleDefaults(
            default_threshold=major_threshold,
            distrust_fallback=True,
            policy_name="greedy",
            policy_config={"major_top_k": 1, "middle_top_k": 1},
            scorer_config={"ranking_contract": "ranking_v2"},
        )

        for node in bundle.nodes.values():
            if node.stage == "major":
                node.threshold = major_threshold
                node.instruction_template = self._major_prompt()
            elif node.stage == "middle":
                node.threshold = middle_threshold
                node.instruction_template = self._middle_prompt()
            else:
                node.threshold = cwe_threshold
                node.instruction_template = self._cwe_prompt()

            node.metadata = dict(node.metadata)
            node.metadata["optimized_prompt"] = True
            node.metadata["description"] = self._description_for(node.target_label)

        bundle.training_metadata = dict(bundle.training_metadata)
        bundle.training_metadata.update(
            {
                "version": "optimized-cascade-1.0",
                "optimizer": "ranking_v2_threshold_tuning",
                "major_threshold": major_threshold,
                "middle_threshold": middle_threshold,
                "cwe_threshold": cwe_threshold,
                "prompt_contract": "ranking_v2",
                "active_cwd_count": len(self.active_cwds),
                "excluded_cwds": list(self.excluded_cwds),
            }
        )
        return bundle

    def _prune_bundle(self, bundle: PromptBundle) -> PromptBundle:
        active_cwe_node_ids = {
            node_id
            for node_id, node in bundle.taxonomy.nodes.items()
            if node.stage == "cwe" and node.label in self.active_cwds
        }
        active_middle_node_ids = {
            bundle.taxonomy.parent_of(node_id)
            for node_id in active_cwe_node_ids
            if bundle.taxonomy.parent_of(node_id) is not None
        }
        active_major_node_ids = {
            bundle.taxonomy.parent_of(node_id)
            for node_id in active_middle_node_ids
            if bundle.taxonomy.parent_of(node_id) is not None
        }
        benign_node_ids = {
            node_id
            for node_id, node in bundle.taxonomy.nodes.items()
            if node.stage == "major" and node.label == bundle.taxonomy.benign_label
        }
        kept_node_ids = (
            active_cwe_node_ids
            | active_middle_node_ids
            | active_major_node_ids
            | benign_node_ids
        )

        pruned_taxonomy_nodes = {
            node_id: node
            for node_id, node in bundle.taxonomy.nodes.items()
            if node_id in kept_node_ids
        }
        pruned_bundle_nodes = {
            node_id: spec
            for node_id, spec in bundle.nodes.items()
            if node_id in kept_node_ids
        }
        bundle.taxonomy = bundle.taxonomy.__class__(
            version=f"{bundle.taxonomy.version}-pruned-min-samples",
            stage_order=bundle.taxonomy.stage_order,
            nodes=pruned_taxonomy_nodes,
            benign_label=bundle.taxonomy.benign_label,
        )
        bundle.nodes = pruned_bundle_nodes
        return bundle

    def _description_for(self, label: str) -> str:
        if label == "Benign":
            return "Safe or fixed code with no actionable vulnerability."
        if label in self.cwd_definitions:
            definition = self.cwd_definitions[label]
            name = str(definition.get("name", ""))
            description = str(definition.get("description", ""))
            return f"{label} {name}\n{description[:1200]}".strip()
        return label

    @staticmethod
    def _major_prompt() -> str:
        return """You are a security classifier for the MAJOR stage.

Pick the best label from the candidate set for this code.

## Target label
{target_label}

## Candidate labels
{candidates}

## Parent label
{parent_label}

## Code
```c
{code}
```

## Output (JSON only)
{
  "predictions": [
    {"category": "<candidate label>", "confidence": 0.0, "reason": "<short reason>"},
    {"category": "<candidate label>", "confidence": 0.0, "reason": "<short reason>"}
  ]
}
"""

    @staticmethod
    def _middle_prompt() -> str:
        return """You are a security classifier for the MIDDLE stage.

The parent route is `{parent_label}`. Rank the candidate labels for the code.

## Target label
{target_label}

## Candidate labels
{candidates}

## Code
```c
{code}
```

## Output (JSON only)
{
  "predictions": [
    {"category": "<candidate label>", "confidence": 0.0, "reason": "<short reason>"},
    {"category": "<candidate label>", "confidence": 0.0, "reason": "<short reason>"}
  ]
}
"""

    @staticmethod
    def _cwe_prompt() -> str:
        return """You are a security classifier for the CWD stage.

The parent route is `{parent_label}`. Rank the candidate CWD labels for the code.

## Target label
{target_label}

## Candidate labels
{candidates}

## Code
```c
{code}
```

## Output (JSON only)
{
  "predictions": [
    {"cwe": "<candidate CWD>", "confidence": 0.0, "reason": "<short reason>"},
    {"cwe": "<candidate CWD>", "confidence": 0.0, "reason": "<short reason>"}
  ]
}
"""


class PrototypeSimilarityIndex:
    def __init__(
        self,
        *,
        support_records: Sequence[SampleRecord],
        cwd_definitions: Mapping[str, Mapping[str, Any]],
        support_top_k: int,
        char_ngram_range: tuple[int, int],
        max_features: int,
    ):
        self.support_records = list(support_records)
        self.cwd_definitions = cwd_definitions
        self.support_top_k = support_top_k
        self.stage_label_texts = self._build_stage_label_texts(cwd_definitions)
        self.middle_to_cwds = {middle: list(get_cwds_for_middle(middle)) for middle in get_middle_categories()}
        self.major_to_cwds = defaultdict(list)
        for middle, cwds in self.middle_to_cwds.items():
            major = get_hierarchy_path(cwds[0])[0] if cwds else None
            if major:
                self.major_to_cwds[major].extend(cwds)
        self.vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=char_ngram_range,
            sublinear_tf=True,
            max_features=max_features,
        )
        self.query_vector_cache: dict[str, csr_matrix] = {}
        self.rank_cache: dict[tuple[str, str, tuple[str, ...]], list[tuple[str, float]]] = {}
        self.raw_score_cache: dict[tuple[str, str, str], float] = {}

        corpus = [self._stage_doc(record) for record in self.support_records]
        corpus.extend(self.stage_label_texts["all"].values())
        self.vectorizer.fit(corpus)

        self.label_prototypes: dict[str, dict[str, csr_matrix]] = {
            "major": {},
            "middle": {},
            "cwe": {},
            "flat": {},
        }
        self.label_support_vectors: dict[str, dict[str, csr_matrix]] = {
            "major": {},
            "middle": {},
            "cwe": {},
            "flat": {},
        }
        self._build_vectors()

    def _build_stage_label_texts(
        self,
        cwd_definitions: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, dict[str, str]]:
        label_texts: dict[str, dict[str, str]] = {
            "major": {},
            "middle": {},
            "cwe": {},
            "flat": {},
            "all": {},
        }

        active_cwds = sorted(
            label
            for label in cwd_definitions.keys()
            if get_hierarchy_path(label)[0] is not None
        )
        for cwd_id in active_cwds:
            definition = cwd_definitions[cwd_id]
            name = str(definition.get("name", ""))
            description = str(definition.get("description", ""))
            text = f"{cwd_id}\n{name}\n{description[:1600]}".strip()
            label_texts["cwe"][cwd_id] = text
            label_texts["flat"][cwd_id] = text
            label_texts["all"][f"cwe::{cwd_id}"] = text

        middle_to_major = {}
        for cwd_id in active_cwds:
            major, middle, _ = get_hierarchy_path(cwd_id)
            if middle:
                middle_to_major[middle] = major

        for middle in get_middle_categories():
            child_text = "\n".join(
                label_texts["cwe"].get(cwd_id, cwd_id)
                for cwd_id in get_cwds_for_middle(middle)
            )
            text = f"{middle}\n{child_text}".strip()
            label_texts["middle"][middle] = text
            label_texts["all"][f"middle::{middle}"] = text

        for major in get_major_categories():
            middle_blocks = [
                label_texts["middle"][middle]
                for middle in get_middle_categories()
                if middle_to_major.get(middle) == major
            ]
            text = f"{major}\n" + "\n".join(middle_blocks)
            label_texts["major"][major] = text.strip()
            label_texts["all"][f"major::{major}"] = text.strip()

        benign_text = (
            "Benign\nsafe code\nproper validation\nbounds checks\n"
            "parameterized query\nnull check\nresource cleanup\nno vulnerability"
        )
        for stage in ("major", "middle", "cwe", "flat"):
            label_texts[stage]["Benign"] = benign_text
        label_texts["all"]["benign"] = benign_text
        return label_texts

    def _stage_doc(self, record: SampleRecord) -> str:
        if record.is_benign:
            return f"Benign\n{record.code}"
        pieces = [record.code]
        if record.cwe:
            pieces.append(self.stage_label_texts["cwe"].get(record.cwe, record.cwe))
        if record.middle:
            pieces.append(record.middle)
        if record.major:
            pieces.append(record.major)
        return "\n".join(piece for piece in pieces if piece)

    def _build_vectors(self) -> None:
        by_stage_label: dict[str, dict[str, list[str]]] = {
            "major": defaultdict(list),
            "middle": defaultdict(list),
            "cwe": defaultdict(list),
            "flat": defaultdict(list),
        }
        for record in self.support_records:
            doc = self._stage_doc(record)
            if record.is_benign:
                for stage in ("major", "middle", "cwe", "flat"):
                    by_stage_label[stage]["Benign"].append(doc)
                continue

            by_stage_label["major"][record.major or "Benign"].append(doc)
            by_stage_label["middle"][record.middle or "Benign"].append(doc)
            by_stage_label["cwe"][record.cwe or "Benign"].append(doc)
            by_stage_label["flat"][record.cwe or "Benign"].append(doc)

        for stage in ("major", "middle", "cwe", "flat"):
            for label, text in self.stage_label_texts[stage].items():
                self.label_prototypes[stage][label] = self.vectorizer.transform([text])
            for label, docs in by_stage_label[stage].items():
                self.label_support_vectors[stage][label] = self.vectorizer.transform(docs)

    def rank(
        self,
        *,
        stage: str,
        code: str,
        candidate_labels: Sequence[str],
    ) -> list[tuple[str, float]]:
        cache_key = (stage, code[:4000], tuple(candidate_labels))
        if cache_key in self.rank_cache:
            return list(self.rank_cache[cache_key])

        query = self.query_vector_cache.get(code)
        if query is None:
            query = self.vectorizer.transform([code])
            self.query_vector_cache[code] = query
        raw_scores: list[tuple[str, float]] = []
        for label in candidate_labels:
            raw_scores.append((label, self._raw_score(stage=stage, label=label, query=query, code=code)))

        labels = [label for label, _ in raw_scores]
        scores = np.array([score for _, score in raw_scores], dtype=float)
        if np.all(scores <= 0):
            probs = np.ones_like(scores) / max(len(scores), 1)
        else:
            logits = scores * 8.0
            logits -= logits.max()
            probs = np.exp(logits)
            probs /= probs.sum()

        ranking = sorted(
            [(label, float(score)) for label, score in zip(labels, probs)],
            key=lambda pair: pair[1],
            reverse=True,
        )
        self.rank_cache[cache_key] = list(ranking)
        return ranking

    def _raw_score(
        self,
        *,
        stage: str,
        label: str,
        query: csr_matrix,
        code: str,
    ) -> float:
        cache_key = (stage, label, code[:4000])
        if cache_key in self.raw_score_cache:
            return self.raw_score_cache[cache_key]

        if label == "Benign" or stage in {"cwe", "flat"}:
            score = self._label_self_score(stage=stage, label=label, query=query, code=code)
        elif stage == "middle":
            child_scores = [self._label_self_score(stage="flat", label=child, query=query, code=code) for child in self.middle_to_cwds.get(label, [])]
            aggregate = self._aggregate_child_scores(child_scores)
            score = aggregate + self._heuristic_bonus(stage=stage, label=label, code=code)
        else:
            child_scores = [self._label_self_score(stage="flat", label=child, query=query, code=code) for child in self.major_to_cwds.get(label, [])]
            aggregate = self._aggregate_child_scores(child_scores)
            score = aggregate + self._heuristic_bonus(stage=stage, label=label, code=code)

        self.raw_score_cache[cache_key] = score
        return score

    def _label_self_score(
        self,
        *,
        stage: str,
        label: str,
        query: csr_matrix,
        code: str,
    ) -> float:
        prototype_vec = self.label_prototypes[stage].get(label)
        prototype_sim = (
            float(cosine_similarity(query, prototype_vec)[0][0]) if prototype_vec is not None else 0.0
        )
        support_vecs = self.label_support_vectors[stage].get(label)
        support_score = 0.0
        if support_vecs is not None and support_vecs.shape[0] > 0:
            sims = cosine_similarity(query, support_vecs)[0]
            top_k = min(self.support_top_k, sims.shape[0])
            if top_k:
                support_score = float(np.mean(np.sort(sims)[-top_k:]))

        heuristic = self._heuristic_bonus(stage=stage, label=label, code=code)
        if label == "Benign":
            support_weight = 0.56
            prototype_weight = 0.34
        else:
            support_weight = 0.60
            prototype_weight = 0.32
        score = (support_weight * support_score) + (prototype_weight * prototype_sim) + heuristic
        return score

    @staticmethod
    def _aggregate_child_scores(child_scores: Sequence[float]) -> float:
        if not child_scores:
            return 0.0
        top_scores = sorted(child_scores)[-3:]
        return (0.7 * max(top_scores)) + (0.3 * float(np.mean(top_scores)))

    def _heuristic_bonus(self, *, stage: str, label: str, code: str) -> float:
        code_lower = code.lower()
        if label == "Benign":
            suspicious = sum(code_lower.count(token) for token in self._all_vuln_tokens())
            safe = sum(
                code_lower.count(token)
                for token in ["preparedstatement", "setstring(", "bounds", "sanitize", "escape", "null check"]
            )
            return max(0.0, min(0.12, 0.04 + 0.01 * safe - 0.005 * suspicious))

        token_map = MAJOR_KEYWORDS if stage == "major" else MIDDLE_KEYWORDS if stage == "middle" else None
        if token_map and label in token_map:
            hits = sum(code_lower.count(token) for token in token_map[label])
            return min(0.10, 0.01 * hits)
        return 0.0

    @staticmethod
    def _all_vuln_tokens() -> Iterable[str]:
        for mapping in (MAJOR_KEYWORDS, MIDDLE_KEYWORDS):
            for values in mapping.values():
                for value in values:
                    yield value


class PrototypeNodeScorer:
    def __init__(self, bundle: PromptBundle, index: PrototypeSimilarityIndex):
        self.bundle = bundle
        self.index = index

    def score(self, node, ctx: ScorerContext) -> NodeScoreResult:
        stage_name = node.stage if node.stage != "cwe" else "cwe"
        ranking = self.index.rank(stage=stage_name, code=ctx.code[:4000], candidate_labels=ctx.candidate_labels)
        predicted_label, top_confidence = ranking[0]
        target_confidence = next((confidence for label, confidence in ranking if label == node.target_label), 0.0)
        effective_threshold = node.threshold if node.threshold is not None else self.bundle.defaults.default_threshold
        matched_target = predicted_label == node.target_label
        if top_confidence < effective_threshold:
            decision = "abstain"
            reject_label = None
        elif matched_target:
            decision = "accept"
            reject_label = None
        else:
            decision = "reject"
            reject_label = predicted_label

        raw_response = json.dumps(
            {
                "predictions": [
                    {"category": label, "confidence": round(confidence, 4)}
                    for label, confidence in ranking[:5]
                ]
            },
            ensure_ascii=False,
        )
        return NodeScoreResult(
            node_id=node.node_id,
            stage=node.stage,
            target_label=node.target_label,
            predicted_label=predicted_label,
            top_confidence=top_confidence,
            target_confidence=target_confidence,
            ranking=ranking,
            matched_target=matched_target,
            decision=decision,
            reject_label=reject_label,
            parse_status="ok",
            effective_threshold=effective_threshold,
            raw_response=raw_response,
            metadata={"backend": "prototype"},
        )


def ensure_resolvable(hostname: str) -> tuple[bool, str]:
    try:
        socket.getaddrinfo(hostname, 443)
        return True, "ok"
    except OSError as exc:
        return False, str(exc)


def select_diverse_subsets(
    dataset: CWDDataset,
    *,
    eval_samples: int,
    dev_samples: int,
    vulnerable_ratio: float,
) -> dict[str, list[SampleRecord]]:
    vulnerable = dataset.vulnerable_records[:]
    benign = dataset.benign_records[:]
    eval_vuln_target = min(len(vulnerable), int(round(eval_samples * vulnerable_ratio)))
    dev_vuln_target = min(len(vulnerable), int(round(dev_samples * vulnerable_ratio)))
    eval_benign_target = max(0, eval_samples - eval_vuln_target)
    dev_benign_target = max(0, dev_samples - dev_vuln_target)

    vuln_by_cwe: dict[str, list[SampleRecord]] = defaultdict(list)
    benign_by_cwe: dict[str, list[SampleRecord]] = defaultdict(list)
    for record in vulnerable:
        vuln_by_cwe[record.cwe or "Unknown"].append(record)
    for record in benign:
        benign_by_cwe[record.source_cwd or "Benign"].append(record)
    for values in vuln_by_cwe.values():
        values.sort(key=lambda record: record.sample_id)
    for values in benign_by_cwe.values():
        values.sort(key=lambda record: record.sample_id)

    focus_labels = _focus_labels(vuln_by_cwe, benign_by_cwe)
    eval_vuln: list[SampleRecord] = []
    dev_vuln: list[SampleRecord] = []
    eval_benign: list[SampleRecord] = []
    dev_benign: list[SampleRecord] = []

    for label in focus_labels:
        vuln_pool = vuln_by_cwe.get(label, [])
        benign_pool = benign_by_cwe.get(label, [])

        eval_v_count = 2 if len(vuln_pool) >= 5 else 1
        dev_v_count = 1 if len(vuln_pool) - eval_v_count >= 2 else 0
        eval_b_count = 1 if benign_pool else 0
        dev_b_count = 1 if len(benign_pool) - eval_b_count >= 2 else 0

        eval_vuln.extend(vuln_pool[:eval_v_count])
        dev_vuln.extend(vuln_pool[eval_v_count:eval_v_count + dev_v_count])
        eval_benign.extend(benign_pool[:eval_b_count])
        dev_benign.extend(benign_pool[eval_b_count:eval_b_count + dev_b_count])

        vuln_by_cwe[label] = vuln_pool[eval_v_count + dev_v_count:]
        benign_by_cwe[label] = benign_pool[eval_b_count + dev_b_count:]

    eval_vuln = _fill_remaining(eval_vuln, vuln_by_cwe, eval_vuln_target, reserve=1)
    dev_vuln = _fill_remaining(dev_vuln, vuln_by_cwe, dev_vuln_target, reserve=1)
    eval_benign = _fill_remaining(eval_benign, benign_by_cwe, eval_benign_target, reserve=0)
    dev_benign = _fill_remaining(dev_benign, benign_by_cwe, dev_benign_target, reserve=0)

    eval_set = eval_vuln[:eval_vuln_target] + eval_benign[:eval_benign_target]
    dev_set = dev_vuln[:dev_vuln_target] + dev_benign[:dev_benign_target]
    used_ids = {record.sample_id for record in eval_set + dev_set}
    support_set = [record for record in dataset.records if record.sample_id not in used_ids]
    return {"eval": eval_set, "dev": dev_set, "support": support_set}


def _focus_labels(
    vuln_by_cwe: Mapping[str, Sequence[SampleRecord]],
    benign_by_cwe: Mapping[str, Sequence[SampleRecord]],
) -> list[str]:
    qualified = {
        label
        for label, records in vuln_by_cwe.items()
        if len(records) >= 5 and len(benign_by_cwe.get(label, [])) >= 3
    }

    middle_best: dict[str, str] = {}
    for label, records in vuln_by_cwe.items():
        if not records:
            continue
        record = records[0]
        middle = record.middle or "Unknown"
        current = middle_best.get(middle)
        if current is None or len(vuln_by_cwe[label]) > len(vuln_by_cwe[current]):
            middle_best[middle] = label

    focused = qualified | set(middle_best.values())
    return sorted(
        focused,
        key=lambda label: (
            get_hierarchy_path(label)[0] or "Unknown",
            get_hierarchy_path(label)[1] or "Unknown",
            -len(vuln_by_cwe.get(label, [])),
            label,
        ),
    )


def _fill_remaining(
    selected: list[SampleRecord],
    pools: Mapping[str, list[SampleRecord]],
    target: int,
    *,
    reserve: int,
) -> list[SampleRecord]:
    selected_ids = {record.sample_id for record in selected}
    while len(selected) < target:
        candidates = [
            (label, records[0], len(records))
            for label, records in pools.items()
            if len(records) > reserve and records[0].sample_id not in selected_ids
        ]
        if not candidates:
            break
        candidates.sort(
            key=lambda item: (
                get_hierarchy_path(item[0])[0] or "Unknown",
                get_hierarchy_path(item[0])[1] or "Unknown",
                -item[2],
                item[0],
            )
        )
        label, record, _ = candidates[0]
        selected.append(record)
        selected_ids.add(record.sample_id)
        pools[label].pop(0)
    return selected


def _pick_vulnerable(records: Sequence[SampleRecord], target: int) -> list[SampleRecord]:
    by_cwe: dict[str, list[SampleRecord]] = defaultdict(list)
    for record in records:
        by_cwe[record.cwe or "Unknown"].append(record)
    for values in by_cwe.values():
        values.sort(key=lambda record: record.sample_id)

    selected: list[SampleRecord] = []
    selected_per_label = Counter()
    selected_per_major = Counter()
    labels = sorted(
        by_cwe.keys(),
        key=lambda label: (
            get_hierarchy_path(label)[0] if label != "Unknown" else "Unknown",
            get_hierarchy_path(label)[1] if label != "Unknown" else "Unknown",
            len(by_cwe[label]),
            label,
        ),
    )

    for label in labels:
        if len(selected) >= target:
            break
        if by_cwe[label]:
            record = by_cwe[label].pop(0)
            selected.append(record)
            selected_per_label[label] += 1
            selected_per_major[record.major] += 1

    while len(selected) < target:
        candidates = [
            (label, records_for_label[0])
            for label, records_for_label in by_cwe.items()
            if records_for_label
        ]
        if not candidates:
            break
        candidates.sort(
            key=lambda item: (
                selected_per_major[item[1].major],
                selected_per_label[item[0]],
                len(by_cwe[item[0]]),
                item[0],
            )
        )
        label, record = candidates[0]
        by_cwe[label].pop(0)
        selected.append(record)
        selected_per_label[label] += 1
        selected_per_major[record.major] += 1

    return selected[:target]


def _pick_benign(
    records: Sequence[SampleRecord],
    target: int,
    *,
    preferred_cwds: set[str | None],
) -> list[SampleRecord]:
    by_source: dict[str, list[SampleRecord]] = defaultdict(list)
    for record in records:
        key = record.source_cwd or "Benign"
        by_source[key].append(record)
    for values in by_source.values():
        values.sort(key=lambda record: record.sample_id)

    selected: list[SampleRecord] = []
    picked_sources: set[str] = set()
    preferred = [source for source in sorted(preferred_cwds) if source and source in by_source]
    for source in preferred:
        if len(selected) >= target:
            break
        if by_source[source]:
            selected.append(by_source[source].pop(0))
            picked_sources.add(source)

    for source in sorted(by_source.keys()):
        if len(selected) >= target:
            break
        if source in picked_sources:
            continue
        if by_source[source]:
            selected.append(by_source[source].pop(0))
            picked_sources.add(source)

    for record in sorted(
        [record for source_records in by_source.values() for record in source_records],
        key=lambda record: record.sample_id,
    ):
        if len(selected) >= target:
            break
        selected.append(record)
    return selected[:target]


def to_eval_samples(records: Sequence[SampleRecord]) -> list[EvaluationSample]:
    samples: list[EvaluationSample] = []
    for record in records:
        samples.append(
            EvaluationSample(
                sample_id=record.sample_id,
                code=record.code,
                major_label=None if record.is_benign else record.major,
                middle_label=None if record.is_benign else record.middle,
                cwe_label=None if record.is_benign else record.cwe,
                final_label=record.final_label,
                metadata={"variant": record.variant, "source_cwd": record.source_cwd},
            )
        )
    return samples


def grid_search_thresholds(
    *,
    bundle_factory: OptimizedBundleFactory,
    index: PrototypeSimilarityIndex,
    dev_samples: Sequence[EvaluationSample],
) -> dict[str, Any]:
    evaluator = MainlineEvaluator()
    policy = GreedyCascadePolicy(major_top_k=1, middle_top_k=1)
    grid_major = [0.16, 0.18, 0.20, 0.22, 0.24, 0.26]
    grid_middle = [0.14, 0.16, 0.18, 0.20, 0.22]
    grid_cwe = [0.12, 0.14, 0.16, 0.18, 0.20]

    best: dict[str, Any] | None = None
    tried: list[dict[str, float]] = []
    for major_threshold in grid_major:
        for middle_threshold in grid_middle:
            for cwe_threshold in grid_cwe:
                bundle = bundle_factory.build(
                    major_threshold=major_threshold,
                    middle_threshold=middle_threshold,
                    cwe_threshold=cwe_threshold,
                )
                scorer = PrototypeNodeScorer(bundle, index)
                result = evaluator.evaluate(bundle, scorer, policy, dev_samples)
                metrics = result.end_to_end_metrics
                route = result.route_metrics
                objective = (
                    metrics["final_exact_match"],
                    metrics["cwe_accuracy"],
                    metrics["major_accuracy"],
                    route["path_coverage"],
                )
                tried.append(
                    {
                        "major_threshold": major_threshold,
                        "middle_threshold": middle_threshold,
                        "cwe_threshold": cwe_threshold,
                        "final_exact_match": metrics["final_exact_match"],
                        "major_accuracy": metrics["major_accuracy"],
                        "middle_accuracy": metrics["middle_accuracy"],
                        "cwe_accuracy": metrics["cwe_accuracy"],
                        "path_coverage": route["path_coverage"],
                    }
                )
                if best is None or objective > best["objective"]:
                    best = {
                        "objective": objective,
                        "major_threshold": major_threshold,
                        "middle_threshold": middle_threshold,
                        "cwe_threshold": cwe_threshold,
                        "metrics": metrics,
                        "route_metrics": route,
                    }
    assert best is not None
    return {"best": best, "grid": tried}


def run_cascade(
    *,
    bundle: PromptBundle,
    scorer,
    samples: Sequence[EvaluationSample],
) -> dict[str, Any]:
    evaluator = MainlineEvaluator()
    policy = GreedyCascadePolicy(major_top_k=1, middle_top_k=1)
    aggregate = evaluator.evaluate(bundle, scorer, policy, samples)
    traces = []
    for sample in samples:
        inference = policy.run(bundle, scorer, sample.code)
        traces.append(
            {
                "sample_id": sample.sample_id,
                "truth": {
                    "final": sample.final_label,
                    "major": sample.major_label,
                    "middle": sample.middle_label,
                    "cwe": sample.cwe_label,
                },
                "prediction": inference.prediction,
                "best_path": (
                    {
                        "labels": [
                            {
                                "stage": result.stage,
                                "target": result.target_label,
                                "confidence": result.target_confidence,
                            }
                            for result in inference.best_path.stage_results
                        ],
                        "score": inference.best_path.score,
                    }
                    if inference.best_path is not None
                    else None
                ),
                "stage_results": {
                    stage: [
                        {
                            "target": result.target_label,
                            "predicted_label": result.predicted_label,
                            "decision": result.decision,
                            "target_confidence": round(result.target_confidence, 4),
                            "top_confidence": round(result.top_confidence, 4),
                            "ranking": [[label, round(conf, 4)] for label, conf in result.ranking[:5]],
                        }
                        for result in stage_results[:5]
                    ]
                    for stage, stage_results in inference.stage_results.items()
                },
                "candidate_path_count": len(inference.candidate_paths),
            }
        )

    stage_activity = {
        "major_accept_rate": _mean(
            1.0 if any(item["decision"] == "accept" for item in trace["stage_results"]["major"]) else 0.0
            for trace in traces
        ),
        "middle_stage_trigger_rate": _mean(1.0 if trace["stage_results"]["middle"] else 0.0 for trace in traces),
        "cwe_stage_trigger_rate": _mean(1.0 if trace["stage_results"]["cwe"] else 0.0 for trace in traces),
        "non_benign_prediction_rate": _mean(1.0 if trace["prediction"] != "Benign" else 0.0 for trace in traces),
    }

    return {
        "aggregate": {
            "route_metrics": aggregate.route_metrics,
            "end_to_end_metrics": aggregate.end_to_end_metrics,
            "cost_metrics": aggregate.cost_metrics,
        },
        "node_metrics": {node_id: asdict(metrics) for node_id, metrics in aggregate.node_metrics.items()},
        "stage_activity": stage_activity,
        "traces": traces,
    }


def run_flat_baseline(
    *,
    index: PrototypeSimilarityIndex,
    dev_records: Sequence[SampleRecord],
    eval_records: Sequence[SampleRecord],
) -> dict[str, Any]:
    candidate_labels = sorted(label for label in index.stage_label_texts["flat"].keys() if label != "Benign") + ["Benign"]
    grid = [0.12, 0.14, 0.16, 0.18, 0.20]
    best: dict[str, Any] | None = None
    for threshold in grid:
        predictions = []
        for record in dev_records:
            ranking = index.rank(stage="flat", code=record.code, candidate_labels=candidate_labels)
            label, confidence = ranking[0]
            prediction = label if confidence >= threshold else "Benign"
            predictions.append((record.final_label, prediction))

        accuracy = _accuracy_from_pairs(predictions)
        binary_f1 = _binary_f1_from_pairs(predictions, positive="Benign", invert=True)
        candidate = {"threshold": threshold, "accuracy": accuracy, "vuln_vs_benign_f1": binary_f1}
        if best is None or (accuracy, binary_f1) > (best["accuracy"], best["vuln_vs_benign_f1"]):
            best = candidate

    assert best is not None
    traces = []
    pairs = []
    for record in eval_records:
        ranking = index.rank(stage="flat", code=record.code, candidate_labels=candidate_labels)
        label, confidence = ranking[0]
        prediction = label if confidence >= best["threshold"] else "Benign"
        pairs.append((record.final_label, prediction))
        traces.append(
            {
                "sample_id": record.sample_id,
                "truth": record.final_label,
                "prediction": prediction,
                "top_confidence": round(confidence, 4),
                "ranking": [[item[0], round(item[1], 4)] for item in ranking[:5]],
            }
        )

    best = dict(best)
    best["eval_accuracy"] = _accuracy_from_pairs(pairs)
    best["eval_vuln_vs_benign_f1"] = _binary_f1_from_pairs(pairs, positive="Benign", invert=True)
    best["pairs"] = pairs
    best["traces"] = traces
    return best


def compare_with_baselines(
    *,
    cascade_pairs: Sequence[tuple[str, str]],
    flat_pairs: Sequence[tuple[str, str]],
    reported_baselines: Mapping[str, float],
) -> dict[str, Any]:
    n = len(cascade_pairs)
    cascade_acc = _accuracy_from_pairs(cascade_pairs)
    flat_acc = _accuracy_from_pairs(flat_pairs)
    wilson = wilson_interval(sum(int(truth == pred) for truth, pred in cascade_pairs), n)

    cascade_correct = [truth == pred for truth, pred in cascade_pairs]
    flat_correct = [truth == pred for truth, pred in flat_pairs]
    b = sum(1 for c_ok, f_ok in zip(cascade_correct, flat_correct) if c_ok and not f_ok)
    c = sum(1 for c_ok, f_ok in zip(cascade_correct, flat_correct) if not c_ok and f_ok)

    return {
        "same_subset": {
            "cascade_accuracy": cascade_acc,
            "flat_accuracy": flat_acc,
            "delta_vs_flat": cascade_acc - flat_acc,
            "mcnemar": mcnemar_exact(b, c),
            "discordant_pairs": {"cascade_only_correct": b, "flat_only_correct": c},
        },
        "reported_baselines": {
            name: {
                "baseline_accuracy": accuracy,
                "delta": cascade_acc - accuracy,
                "binomial_test": exact_binomial_test(
                    k=sum(int(truth == pred) for truth, pred in cascade_pairs),
                    n=n,
                    p0=accuracy,
                ),
            }
            for name, accuracy in reported_baselines.items()
        },
        "wilson_interval_95": {"low": wilson[0], "high": wilson[1]},
    }


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denominator = 1 + (z * z) / n
    center = (p + (z * z) / (2 * n)) / denominator
    margin = z * math.sqrt((p * (1 - p) + (z * z) / (4 * n)) / n) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def exact_binomial_test(k: int, n: int, p0: float) -> dict[str, float | str]:
    if n == 0:
        return {"alternative": "two-sided", "p_value": 1.0}
    observed = k / n
    alternative = "greater" if observed >= p0 else "less"

    def pmf(i: int) -> float:
        return math.comb(n, i) * (p0**i) * ((1 - p0) ** (n - i))

    if alternative == "greater":
        p_value = sum(pmf(i) for i in range(k, n + 1))
    else:
        p_value = sum(pmf(i) for i in range(0, k + 1))
    return {"alternative": alternative, "p_value": min(1.0, p_value)}


def mcnemar_exact(b: int, c: int) -> dict[str, float]:
    n = b + c
    if n == 0:
        return {"p_value": 1.0}
    tail = sum(math.comb(n, i) for i in range(0, min(b, c) + 1)) / (2**n)
    return {"p_value": min(1.0, 2 * tail)}


def _accuracy_from_pairs(pairs: Sequence[tuple[str, str]]) -> float:
    return _mean(1.0 if truth == pred else 0.0 for truth, pred in pairs)


def _binary_f1_from_pairs(
    pairs: Sequence[tuple[str, str]],
    *,
    positive: str,
    invert: bool = False,
) -> float:
    tp = fp = fn = 0
    for truth, pred in pairs:
        truth_positive = truth != positive if invert else truth == positive
        pred_positive = pred != positive if invert else pred == positive
        if truth_positive and pred_positive:
            tp += 1
        elif not truth_positive and pred_positive:
            fp += 1
        elif truth_positive and not pred_positive:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0


def _mean(values: Iterable[float]) -> float:
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def summarize_selection(records: Sequence[SampleRecord]) -> dict[str, Any]:
    return {
        "total": len(records),
        "variant_counts": dict(Counter(record.variant for record in records)),
        "major_counts": dict(Counter(record.major for record in records)),
        "middle_counts": dict(Counter(record.middle for record in records if record.middle)),
        "cwe_counts": dict(Counter(record.cwe for record in records if record.cwe)),
        "languages": dict(Counter(record.language for record in records)),
    }


def validate_architecture(
    bundle: PromptBundle,
    support_records: Sequence[SampleRecord],
    dataset_filter: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    major_nodes = [node for node in bundle.taxonomy.nodes.values() if node.stage == "major"]
    middle_nodes = [node for node in bundle.taxonomy.nodes.values() if node.stage == "middle"]
    cwe_nodes = [node for node in bundle.taxonomy.nodes.values() if node.stage == "cwe"]
    active_majors = sorted({record.major for record in support_records if record.major and record.major != "Benign"})
    active_middles = sorted({record.middle for record in support_records if record.middle})
    active_cwes = sorted({record.cwe for record in support_records if record.cwe})
    missing_middle_parents = [node.node_id for node in middle_nodes if node.parent_id is None]
    missing_cwe_parents = [node.node_id for node in cwe_nodes if node.parent_id is None]
    return {
        "total_nodes": len(bundle.nodes),
        "major_nodes": len(major_nodes),
        "middle_nodes": len(middle_nodes),
        "cwe_nodes": len(cwe_nodes),
        "missing_middle_parents": missing_middle_parents,
        "missing_cwe_parents": missing_cwe_parents,
        "active_majors_in_support": active_majors,
        "active_middles_in_support": active_middles,
        "active_cwes_in_support": active_cwes,
        "excluded_cwds": list(dataset_filter.get("excluded_cwds", [])) if dataset_filter else [],
        "note": (
            "The active taxonomy is pruned to CWD nodes that meet the current "
            f"minimum vulnerable-sample floor of {dataset_filter.get('min_cwe_vulnerable_samples', 0)}."
            if dataset_filter
            else "Architecture validation ran without dataset-level pruning metadata."
        ),
    }


def render_report(results: Mapping[str, Any]) -> str:
    metrics = results["cascade"]["aggregate"]["end_to_end_metrics"]
    route = results["cascade"]["aggregate"]["route_metrics"]
    comparison = results["baseline_comparison"]
    stage_activity = results["cascade"]["stage_activity"]
    architecture = results["architecture_validation"]
    calibration = results["calibration"]["best"]
    env = results["environment"]
    question_bank_filter = results["question_bank_filter"]
    excluded_nodes = question_bank_filter["excluded_cwds"]
    excluded_text = ", ".join(excluded_nodes) if excluded_nodes else "none"
    return f"""# Optimized CWD Cascade Experiment

## Summary

- Timestamp: {results["timestamp"]}
- Backend used: {results["backend_used"]}
- DNS status: {env["dns_check"]["openrouter.ai"]["ok"]} ({env["dns_check"]["openrouter.ai"]["detail"]})
- Eval samples: {results["sample_selection"]["eval"]["total"]}
- Dev samples: {results["sample_selection"]["dev"]["total"]}

## Active Label Space

- Minimum vulnerable samples per CWD: {question_bank_filter["min_cwe_vulnerable_samples"]}
- Active CWD nodes in question bank/cascade: {question_bank_filter["active_cwd_count"]}
- Excluded low-sample CWD nodes: {question_bank_filter["excluded_cwd_count"]}
- Excluded labels: {excluded_text}

## What Changed From The 0% Run

1. Replaced binary node prompts with explicit `ranking_v2` JSON prompts that list candidate labels.
2. Tuned per-stage thresholds instead of using the blanket `0.5` threshold that caused universal abstention.
3. Expanded evaluation from 8 quick samples to {results["sample_selection"]["eval"]["total"]} diverse samples covering {len(results["sample_selection"]["eval"]["cwe_counts"])} CWD labels.
4. Added per-stage instrumentation, route coverage, trace capture, and baseline comparison on the same subset.
5. Added an offline prototype scorer fallback so the repaired cascade can run in DNS-restricted environments while preserving the same taxonomy and policy.

## Calibration

- Best thresholds: major={calibration["major_threshold"]:.2f}, middle={calibration["middle_threshold"]:.2f}, cwe={calibration["cwe_threshold"]:.2f}
- Dev exact match: {calibration["metrics"]["final_exact_match"]:.3f}
- Dev path coverage: {calibration["route_metrics"]["path_coverage"]:.3f}

## Final Cascade Metrics

| Metric | Value |
|---|---:|
| Final exact match | {metrics["final_exact_match"]:.3f} |
| Major accuracy | {metrics["major_accuracy"]:.3f} |
| Middle accuracy | {metrics["middle_accuracy"]:.3f} |
| CWD accuracy | {metrics["cwe_accuracy"]:.3f} |
| Vulnerable vs Benign F1 | {metrics["vuln_vs_benign_f1"]:.3f} |
| Macro F1 | {metrics["macro_f1"]:.3f} |
| Path coverage | {route["path_coverage"]:.3f} |
| Major route recall@1 | {route["major_route_recall_at_1"]:.3f} |
| Middle route recall@1 | {route["middle_route_recall_at_1"]:.3f} |
| Avg nodes scored/sample | {results["cascade"]["aggregate"]["cost_metrics"]["avg_nodes_scored_per_sample"]:.2f} |

## Stage Activity

- Non-benign prediction rate: {stage_activity["non_benign_prediction_rate"]:.3f}
- Major accept rate: {stage_activity["major_accept_rate"]:.3f}
- Middle trigger rate: {stage_activity["middle_stage_trigger_rate"]:.3f}
- CWD trigger rate: {stage_activity["cwe_stage_trigger_rate"]:.3f}

## Baseline Comparison

| Baseline | Accuracy | Delta vs Cascade |
|---|---:|---:|
| Same-subset flat baseline | {comparison["same_subset"]["flat_accuracy"]:.3f} | {comparison["same_subset"]["delta_vs_flat"]:+.3f} |
| Reported CWD flat baseline | {comparison["reported_baselines"]["cwd_flat_reported"]["baseline_accuracy"]:.3f} | {comparison["reported_baselines"]["cwd_flat_reported"]["delta"]:+.3f} |
| Reported MulVul baseline | {comparison["reported_baselines"]["mulvul_reported"]["baseline_accuracy"]:.3f} | {comparison["reported_baselines"]["mulvul_reported"]["delta"]:+.3f} |
| Previous broken run | {comparison["reported_baselines"]["zero_accuracy_regression"]["baseline_accuracy"]:.3f} | {comparison["reported_baselines"]["zero_accuracy_regression"]["delta"]:+.3f} |

- Same-subset cascade vs flat McNemar p-value: {comparison["same_subset"]["mcnemar"]["p_value"]:.4f}
- Cascade 95% Wilson interval: [{comparison["wilson_interval_95"]["low"]:.3f}, {comparison["wilson_interval_95"]["high"]:.3f}]
- Reported CWD flat exact-binomial ({comparison["reported_baselines"]["cwd_flat_reported"]["binomial_test"]["alternative"]}): {comparison["reported_baselines"]["cwd_flat_reported"]["binomial_test"]["p_value"]:.4f}
- Reported MulVul exact-binomial ({comparison["reported_baselines"]["mulvul_reported"]["binomial_test"]["alternative"]}): {comparison["reported_baselines"]["mulvul_reported"]["binomial_test"]["p_value"]:.4f}

## Architecture Validation

- Repaired node count: {architecture["total_nodes"]} ({architecture["major_nodes"]} major / {architecture["middle_nodes"]} middle / {architecture["cwe_nodes"]} CWD)
- Missing middle parents: {len(architecture["missing_middle_parents"])}
- Missing CWD parents: {len(architecture["missing_cwe_parents"])}
- Active vulnerable majors in this dataset: {", ".join(architecture["active_majors_in_support"])}
- Active middles in this dataset: {", ".join(architecture["active_middles_in_support"])}
- Note: {architecture["note"]}

## Caveat

The script is ready for live OpenRouter execution, but this sandbox could not resolve `openrouter.ai` or `api.anthropic.com`. The saved run therefore used the offline prototype backend while preserving the repaired cascade, prompt bundle, and thresholded routing logic.
"""


def save_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the optimized CWD cascade experiment.")
    parser.add_argument("--eval-samples", type=int, default=80)
    parser.add_argument("--dev-samples", type=int, default=48)
    parser.add_argument("--vulnerable-ratio", type=float, default=0.75)
    parser.add_argument("--min-cwe-vuln-samples", type=int, default=6)
    parser.add_argument("--backend", choices=["auto", "prototype", "openrouter"], default="auto")
    parser.add_argument("--output-root", default="./cwd_optimized_experiment_results")
    args = parser.parse_args()

    config = ExperimentConfig(
        eval_samples=args.eval_samples,
        dev_samples=args.dev_samples,
        vulnerable_ratio=args.vulnerable_ratio,
        min_cwe_vulnerable_samples=args.min_cwe_vuln_samples,
        backend=args.backend,
        output_root=args.output_root,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = (OUTPUT_ROOT / config.output_root / timestamp).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    dns_ok, dns_detail = ensure_resolvable("openrouter.ai")
    anth_ok, anth_detail = ensure_resolvable("api.anthropic.com")
    if config.backend == "openrouter" and not dns_ok:
        raise RuntimeError(f"backend=openrouter requested but DNS failed: {dns_detail}")
    backend_used = "openrouter" if config.backend == "openrouter" or (config.backend == "auto" and dns_ok) else "prototype"

    dataset = CWDDataset(
        SOURCE_ROOT / "cwd_native_dataset.json",
        min_cwe_vulnerable_samples=config.min_cwe_vulnerable_samples,
    )
    subsets = select_diverse_subsets(
        dataset,
        eval_samples=config.eval_samples,
        dev_samples=config.dev_samples,
        vulnerable_ratio=config.vulnerable_ratio,
    )

    bundle_factory = OptimizedBundleFactory(
        dataset.cwd_definitions,
        active_cwds=dataset.active_cwds,
    )
    index = PrototypeSimilarityIndex(
        support_records=subsets["support"],
        cwd_definitions=dataset.cwd_definitions,
        support_top_k=config.support_top_k,
        char_ngram_range=config.char_ngram_range,
        max_features=config.max_features,
    )

    calibration = grid_search_thresholds(
        bundle_factory=bundle_factory,
        index=index,
        dev_samples=to_eval_samples(subsets["dev"]),
    )
    best = calibration["best"]
    bundle = bundle_factory.build(
        major_threshold=best["major_threshold"],
        middle_threshold=best["middle_threshold"],
        cwe_threshold=best["cwe_threshold"],
    )

    if backend_used == "openrouter":
        from mulvul.mainline.scorer import LLMNodeScorer

        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY is required for backend=openrouter")
        client = OpenAICompatibleClient(model_name=config.model_name, api_base=config.api_base, api_key=api_key)
        scorer = LLMNodeScorer(client, bundle)
    else:
        scorer = PrototypeNodeScorer(bundle, index)

    cascade = run_cascade(
        bundle=bundle,
        scorer=scorer,
        samples=to_eval_samples(subsets["eval"]),
    )
    flat_baseline = run_flat_baseline(
        index=index,
        dev_records=subsets["dev"],
        eval_records=subsets["eval"],
    )

    cascade_pairs = [(trace["truth"]["final"], trace["prediction"]) for trace in cascade["traces"]]
    baseline_comparison = compare_with_baselines(
        cascade_pairs=cascade_pairs,
        flat_pairs=flat_baseline["pairs"],
        reported_baselines=config.reported_baselines or DEFAULT_REPORTED_BASELINES,
    )
    architecture = validate_architecture(
        bundle,
        subsets["support"],
        dataset_filter=dataset.filter_summary,
    )

    results = {
        "timestamp": timestamp,
        "backend_requested": config.backend,
        "backend_used": backend_used,
        "config": asdict(config),
        "environment": {
            "dns_check": {
                "openrouter.ai": {"ok": dns_ok, "detail": dns_detail},
                "api.anthropic.com": {"ok": anth_ok, "detail": anth_detail},
            }
        },
        "sample_selection": {
            "eval": summarize_selection(subsets["eval"]),
            "dev": summarize_selection(subsets["dev"]),
            "support": summarize_selection(subsets["support"]),
        },
        "question_bank_filter": dataset.filter_summary,
        "calibration": calibration,
        "architecture_validation": architecture,
        "cascade": cascade,
        "flat_baseline": {key: value for key, value in flat_baseline.items() if key not in {"pairs", "traces"}},
        "baseline_comparison": baseline_comparison,
    }

    report = render_report(results)
    save_json(output_dir / "optimized_bundle.json", bundle.to_dict())
    save_json(output_dir / "results.json", results)
    save_json(output_dir / "sample_selection.json", {
        "eval": [asdict(record) for record in subsets["eval"]],
        "dev": [asdict(record) for record in subsets["dev"]],
    })
    save_json(output_dir / "cascade_traces.json", cascade["traces"])
    save_json(output_dir / "flat_traces.json", flat_baseline["traces"])
    (output_dir / "report.md").write_text(report, encoding="utf-8")

    print(report)
    print(f"\nArtifacts saved to: {output_dir}")


if __name__ == "__main__":
    main()
