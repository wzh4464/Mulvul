#!/usr/bin/env python3
"""Build the CF_P dataset from PrimeVul and CVEfixes."""

from __future__ import annotations

import argparse
import gzip
import json
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional
from urllib.parse import urlparse

from mulvul.data.cwe_hierarchy import CWE_TO_MIDDLE, cwe_to_major

DEFAULT_SEED = 42
DEFAULT_TARGET_PER_CWE = 50
LANGUAGE_MAP = {"Python": "python", "Java": "java"}


@dataclass
class PrimeVulInventory:
    prime_cwe_set: set[str]
    primary_cwe_counts: dict[str, int]
    vulnerable_by_cwe: dict[str, list[dict[str, Any]]]
    sampled_vulnerable_by_cwe: dict[str, list[dict[str, Any]]]
    benign_pool: list[dict[str, Any]]


@dataclass
class TopupBuildResult:
    records: list[dict[str, Any]]
    kept_cwes: list[str]
    dropped_cwes: list[str]
    per_cwe_stats: dict[str, dict[str, Any]]


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_jsonl(records: Iterable[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def primary_cwe_from_record(record: dict[str, Any]) -> Optional[str]:
    cwes = record.get("cwe") or []
    if not cwes:
        return None
    primary = cwes[0]
    if isinstance(primary, str) and primary.startswith("CWE-"):
        return primary
    return None


def _record_sort_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(record.get("idx", "")),
        str(record.get("commit_id", "")),
        str(record.get("func", "")),
    )


def _sample_records(
    records: list[dict[str, Any]],
    limit: int,
    rng: random.Random,
) -> list[dict[str, Any]]:
    ordered = sorted(records, key=_record_sort_key)
    if len(ordered) <= limit:
        return [dict(record) for record in ordered]
    sampled = rng.sample(ordered, limit)
    return [dict(record) for record in sorted(sampled, key=_record_sort_key)]


def build_primevul_inventory(
    records: Iterable[dict[str, Any]],
    *,
    per_cwe_cap: int = DEFAULT_TARGET_PER_CWE,
    seed: int = DEFAULT_SEED,
) -> PrimeVulInventory:
    vulnerable_by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    benign_pool: list[dict[str, Any]] = []

    for raw_record in records:
        record = dict(raw_record)
        target = int(record.get("target", 0))
        if target == 1:
            primary_cwe = primary_cwe_from_record(record)
            if primary_cwe is None:
                continue
            record.setdefault("source", "primevul")
            record["primary_cwe"] = primary_cwe
            vulnerable_by_cwe[primary_cwe].append(record)
        else:
            record.setdefault("source", "primevul")
            record["primary_cwe"] = None
            benign_pool.append(record)

    primary_cwe_counts = {
        cwe: len(bucket) for cwe, bucket in sorted(vulnerable_by_cwe.items())
    }
    rng = random.Random(seed)
    sampled_vulnerable_by_cwe = {
        cwe: _sample_records(bucket, per_cwe_cap, rng)
        for cwe, bucket in sorted(vulnerable_by_cwe.items())
    }
    return PrimeVulInventory(
        prime_cwe_set=set(primary_cwe_counts),
        primary_cwe_counts=primary_cwe_counts,
        vulnerable_by_cwe=dict(vulnerable_by_cwe),
        sampled_vulnerable_by_cwe=sampled_vulnerable_by_cwe,
        benign_pool=sorted(benign_pool, key=_record_sort_key),
    )


def parse_insert_values(line: str) -> list[str]:
    marker = "VALUES("
    start = line.index(marker) + len(marker)
    end = line.rfind(");")
    if end == -1:
        raise ValueError(f"Could not parse SQL insert line: {line[:80]}")
    body = line[start:end]
    values: list[str] = []
    current: list[str] = []
    in_string = False
    paren_depth = 0
    index = 0

    while index < len(body):
        char = body[index]
        if in_string:
            current.append(char)
            if char == "'":
                if index + 1 < len(body) and body[index + 1] == "'":
                    current.append(body[index + 1])
                    index += 1
                else:
                    in_string = False
        else:
            if char == "'":
                in_string = True
                current.append(char)
            elif char == "(":
                paren_depth += 1
                current.append(char)
            elif char == ")":
                paren_depth -= 1
                current.append(char)
            elif char == "," and paren_depth == 0:
                values.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        index += 1

    values.append("".join(current).strip())
    return values


def _split_sql_arguments(body: str) -> list[str]:
    values: list[str] = []
    current: list[str] = []
    in_string = False
    paren_depth = 0
    index = 0

    while index < len(body):
        char = body[index]
        if in_string:
            current.append(char)
            if char == "'":
                if index + 1 < len(body) and body[index + 1] == "'":
                    current.append(body[index + 1])
                    index += 1
                else:
                    in_string = False
        else:
            if char == "'":
                in_string = True
                current.append(char)
            elif char == "(":
                paren_depth += 1
                current.append(char)
            elif char == ")":
                paren_depth -= 1
                current.append(char)
            elif char == "," and paren_depth == 0:
                values.append("".join(current).strip())
                current = []
            else:
                current.append(char)
        index += 1

    values.append("".join(current).strip())
    return values


def decode_sql_value(token: str) -> Any:
    token = token.strip()
    if token == "NULL":
        return None
    if token.startswith("replace(") and token.endswith(")"):
        inner = token[len("replace(") : -1]
        args = _split_sql_arguments(inner)
        if len(args) != 3:
            raise ValueError(f"Unsupported replace() expression: {token}")
        base = decode_sql_value(args[0])
        old = decode_sql_value(args[1])
        new = decode_sql_value(args[2])
        return str(base).replace(str(old), str(new))
    if token.startswith("char(") and token.endswith(")"):
        return chr(int(token[len("char(") : -1]))
    if token.startswith("'") and token.endswith("'"):
        return token[1:-1].replace("''", "'")
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    if re.fullmatch(r"-?\d+\.\d+", token):
        return float(token)
    if token in {"True", "true"}:
        return True
    if token in {"False", "false"}:
        return False
    return token


def parse_bool_token(token: str) -> bool:
    value = decode_sql_value(token)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1"}:
            return True
        if normalized in {"false", "0"}:
            return False
    raise ValueError(f"Cannot interpret token as bool: {token}")


def load_relevant_cwe_map_from_lines(
    lines: Iterable[str],
    allowed_cwe_set: set[str],
) -> dict[str, set[str]]:
    cve_to_prime_cwes: dict[str, set[str]] = defaultdict(set)
    for line in lines:
        if not line.startswith("INSERT INTO cwe_classification VALUES("):
            continue
        values = parse_insert_values(line)
        cve_id = str(decode_sql_value(values[0]))
        cwe_id = str(decode_sql_value(values[1]))
        if cwe_id in allowed_cwe_set:
            cve_to_prime_cwes[cve_id].add(cwe_id)
    return dict(cve_to_prime_cwes)


def load_relevant_cwe_map(
    sql_gz_path: Path,
    allowed_cwe_set: set[str],
) -> dict[str, set[str]]:
    with gzip.open(sql_gz_path, "rt", encoding="utf-8", errors="replace") as handle:
        return load_relevant_cwe_map_from_lines(handle, allowed_cwe_set)


def _derive_project_name(repo_url: str) -> str:
    path = urlparse(repo_url).path.rstrip("/")
    if not path:
        return "unknown"
    project = path.split("/")[-1]
    return project[:-4] if project.endswith(".git") else project


def _maybe_int(value: Any) -> Any:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def _primary_cwe_for_list(
    cwes: Iterable[str],
    preferred_cwe_set: Optional[set[str]] = None,
) -> Optional[str]:
    ordered_cwes = list(cwes)
    if preferred_cwe_set is not None:
        for cwe in ordered_cwes:
            if cwe in preferred_cwe_set:
                return cwe
    return ordered_cwes[0] if ordered_cwes else None


def _record_id(record: dict[str, Any]) -> str:
    idx = record.get("idx")
    if idx is not None:
        return str(idx)
    return "|".join(_record_sort_key(record))


def _known_major_for_cwe(cwe: Optional[str]) -> Optional[str]:
    if cwe is None or cwe not in CWE_TO_MIDDLE:
        return None
    return cwe_to_major([cwe])


def _annotate_topup_record(
    record: dict[str, Any],
    *,
    anchor_cwe: Optional[str],
    anchor_major: Optional[str],
    supplement_strategy: str,
) -> list[dict[str, Any]]:
    annotated = dict(record)
    annotated["anchor_cwe"] = anchor_cwe
    annotated["anchor_major"] = anchor_major
    annotated["supplement_strategy"] = supplement_strategy
    return [annotated]


def extract_cf_p_records_from_lines(
    lines: Iterable[str],
    *,
    cve_to_prime_cwes: dict[str, set[str]],
    allowed_cwe_set: set[str],
    preferred_cwe_set: Optional[set[str]] = None,
) -> list[dict[str, Any]]:
    relevant_hashes: dict[str, list[tuple[str, str]]] = defaultdict(list)
    eligible_file_changes: dict[str, dict[str, Any]] = {}
    records_by_method: dict[str, dict[str, Any]] = {}

    for line in lines:
        if line.startswith("INSERT INTO fixes VALUES("):
            values = parse_insert_values(line)
            cve_id = str(decode_sql_value(values[0]))
            if cve_id not in cve_to_prime_cwes:
                continue
            commit_hash = str(decode_sql_value(values[1]))
            repo_url = str(decode_sql_value(values[2]))
            relevant_hashes[commit_hash].append((cve_id, repo_url))
            continue

        if line.startswith("INSERT INTO file_change VALUES("):
            values = parse_insert_values(line)
            commit_hash = str(decode_sql_value(values[1]))
            if commit_hash not in relevant_hashes:
                continue
            language = str(decode_sql_value(values[-1]))
            if language not in LANGUAGE_MAP:
                continue
            file_change_id = str(decode_sql_value(values[0]))
            filename = decode_sql_value(values[2]) or decode_sql_value(values[4]) or decode_sql_value(values[3])
            eligible_file_changes[file_change_id] = {
                "file_change_id": _maybe_int(decode_sql_value(values[0])),
                "commit_id": commit_hash,
                "file_name": filename,
                "lang": LANGUAGE_MAP[language],
                "repo_fixes": list(relevant_hashes[commit_hash]),
            }
            continue

        if not line.startswith("INSERT INTO method_change VALUES("):
            continue

        values = parse_insert_values(line)
        file_change_id = str(decode_sql_value(values[1]))
        file_change_info = eligible_file_changes.get(file_change_id)
        if file_change_info is None:
            continue
        if not parse_bool_token(values[12]):
            continue

        method_change_id = str(decode_sql_value(values[0]))
        code = decode_sql_value(values[7])
        if not isinstance(code, str) or not code.strip():
            continue

        cwe_set: set[str] = set()
        cve_ids: set[str] = set()
        repo_url = ""
        for cve_id, current_repo_url in file_change_info["repo_fixes"]:
            repo_url = repo_url or current_repo_url
            cve_ids.add(cve_id)
            cwe_set.update(cve_to_prime_cwes.get(cve_id, set()))

        filtered_cwes = sorted(cwe for cwe in cwe_set if cwe in allowed_cwe_set)
        if not filtered_cwes:
            continue

        primary_cwe = _primary_cwe_for_list(filtered_cwes, preferred_cwe_set)
        if primary_cwe is None:
            continue

        record = records_by_method.get(method_change_id)
        if record is None:
            sorted_cve_ids = sorted(cve_ids)
            primary_cve = sorted_cve_ids[0] if sorted_cve_ids else None
            record = {
                "idx": _maybe_int(decode_sql_value(values[0])),
                "target": 1,
                "func": code,
                "cwe": filtered_cwes,
                "primary_cwe": primary_cwe,
                "cve": primary_cve,
                "cve_list": sorted_cve_ids,
                "cve_desc": None,
                "nvd_url": (
                    f"https://nvd.nist.gov/vuln/detail/{primary_cve}"
                    if primary_cve
                    else None
                ),
                "project": _derive_project_name(repo_url),
                "project_url": repo_url,
                "commit_id": file_change_info["commit_id"],
                "commit_message": None,
                "commit_url": None,
                "file_name": file_change_info["file_name"],
                "file_hash": None,
                "func_hash": None,
                "source": "cvefixes",
                "lang": file_change_info["lang"],
                "method_change_id": _maybe_int(method_change_id),
                "file_change_id": file_change_info["file_change_id"],
            }
            records_by_method[method_change_id] = record
        else:
            record["cwe"] = sorted(set(record["cwe"]) | set(filtered_cwes))
            record["cve_list"] = sorted(set(record["cve_list"]) | cve_ids)
            record["primary_cwe"] = _primary_cwe_for_list(
                record["cwe"],
                preferred_cwe_set,
            )
            if record["cve_list"] and record["cve"] is None:
                record["cve"] = record["cve_list"][0]

    return sorted(records_by_method.values(), key=_record_sort_key)


def extract_cf_p_records(
    sql_gz_path: Path,
    *,
    cve_to_prime_cwes: dict[str, set[str]],
    allowed_cwe_set: set[str],
    preferred_cwe_set: Optional[set[str]] = None,
) -> list[dict[str, Any]]:
    with gzip.open(sql_gz_path, "rt", encoding="utf-8", errors="replace") as handle:
        return extract_cf_p_records_from_lines(
            handle,
            cve_to_prime_cwes=cve_to_prime_cwes,
            allowed_cwe_set=allowed_cwe_set,
            preferred_cwe_set=preferred_cwe_set,
        )


def build_topup_dataset(
    inventory: PrimeVulInventory,
    cf_p_records: Iterable[dict[str, Any]],
    *,
    target_per_cwe: int = DEFAULT_TARGET_PER_CWE,
    seed: int = DEFAULT_SEED,
) -> TopupBuildResult:
    rng = random.Random(seed)
    cf_p_by_cwe: dict[str, list[dict[str, Any]]] = defaultdict(list)
    cf_p_by_major: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw_record in cf_p_records:
        record = dict(raw_record)
        primary_cwe = record.get("primary_cwe") or _primary_cwe_for_list(record.get("cwe", []))
        if primary_cwe is None:
            continue
        record["primary_cwe"] = primary_cwe
        cf_p_by_cwe[primary_cwe].append(record)
        major = _known_major_for_cwe(primary_cwe)
        if major is not None:
            cf_p_by_major[major].append(record)

    vulnerable_records: list[dict[str, Any]] = []
    kept_cwes: list[str] = []
    dropped_cwes: list[str] = []
    per_cwe_stats: dict[str, dict[str, Any]] = {}
    used_cf_record_ids: set[str] = set()

    for cwe in sorted(inventory.prime_cwe_set):
        prime_selected = list(inventory.sampled_vulnerable_by_cwe.get(cwe, []))
        needed = max(0, target_per_cwe - len(prime_selected))
        target_major = _known_major_for_cwe(cwe)

        same_cwe_available = [
            record
            for record in sorted(cf_p_by_cwe.get(cwe, []), key=_record_sort_key)
            if _record_id(record) not in used_cf_record_ids
        ]
        same_cwe_take = min(needed, len(same_cwe_available))
        chosen_same_cwe = (
            _sample_records(same_cwe_available, same_cwe_take, rng)
            if same_cwe_take
            else []
        )

        chosen_same_cwe_ids = {_record_id(record) for record in chosen_same_cwe}
        remaining = needed - len(chosen_same_cwe)
        same_major_available: list[dict[str, Any]] = []
        chosen_same_major: list[dict[str, Any]] = []
        if remaining and target_major is not None:
            same_major_available = [
                record
                for record in sorted(cf_p_by_major.get(target_major, []), key=_record_sort_key)
                if record.get("primary_cwe") != cwe
                and _record_id(record) not in used_cf_record_ids
                and _record_id(record) not in chosen_same_cwe_ids
            ]
            if len(same_major_available) >= remaining:
                chosen_same_major = _sample_records(same_major_available, remaining, rng)

        if len(chosen_same_cwe) + len(chosen_same_major) < needed:
            dropped_cwes.append(cwe)
            per_cwe_stats[cwe] = {
                "prime_total": inventory.primary_cwe_counts.get(cwe, 0),
                "prime_selected": len(prime_selected),
                "target_major": target_major,
                "cf_same_cwe_available": len(same_cwe_available),
                "cf_same_cwe_selected": 0,
                "cf_same_major_available": len(same_major_available),
                "cf_same_major_selected": 0,
                "cf_available": len(same_cwe_available) + len(same_major_available),
                "cf_selected": 0,
                "same_major_replacement_cwe_counts": {},
                "kept": False,
            }
            continue

        chosen_cf = chosen_same_cwe + chosen_same_major
        used_cf_record_ids.update(_record_id(record) for record in chosen_cf)
        replacement_cwe_counts = Counter(
            str(record["primary_cwe"])
            for record in chosen_same_major
            if record.get("primary_cwe") is not None
        )
        for record in prime_selected:
            vulnerable_records.extend(
                _annotate_topup_record(
                    record,
                    anchor_cwe=cwe,
                    anchor_major=target_major,
                    supplement_strategy="primevul_anchor",
                )
            )
        for record in chosen_same_cwe:
            vulnerable_records.extend(
                _annotate_topup_record(
                    record,
                    anchor_cwe=cwe,
                    anchor_major=target_major,
                    supplement_strategy="same_cwe_direct",
                )
            )
        for record in chosen_same_major:
            vulnerable_records.extend(
                _annotate_topup_record(
                    record,
                    anchor_cwe=cwe,
                    anchor_major=target_major,
                    supplement_strategy="same_major_replacement",
                )
            )
        kept_cwes.append(cwe)
        per_cwe_stats[cwe] = {
            "prime_total": inventory.primary_cwe_counts.get(cwe, 0),
            "prime_selected": len(prime_selected),
            "target_major": target_major,
            "cf_same_cwe_available": len(same_cwe_available),
            "cf_same_cwe_selected": len(chosen_same_cwe),
            "cf_same_major_available": len(same_major_available),
            "cf_same_major_selected": len(chosen_same_major),
            "cf_available": len(same_cwe_available) + len(same_major_available),
            "cf_selected": len(chosen_cf),
            "same_major_replacement_cwe_counts": dict(sorted(replacement_cwe_counts.items())),
            "kept": True,
        }

    benign_needed = len(vulnerable_records)
    benign_records = _sample_records(inventory.benign_pool, benign_needed, rng)
    annotated_benign_records: list[dict[str, Any]] = []
    for record in benign_records:
        record.setdefault("source", "primevul")
        record["primary_cwe"] = None
        annotated_benign_records.extend(
            _annotate_topup_record(
                record,
                anchor_cwe=None,
                anchor_major=None,
                supplement_strategy="benign",
            )
        )

    final_records = list(vulnerable_records) + annotated_benign_records
    rng.shuffle(final_records)
    return TopupBuildResult(
        records=final_records,
        kept_cwes=kept_cwes,
        dropped_cwes=dropped_cwes,
        per_cwe_stats=per_cwe_stats,
    )


def build_stats(
    inventory: PrimeVulInventory,
    cf_p_records: list[dict[str, Any]],
    topup_result: TopupBuildResult,
    topup_candidate_records: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    candidate_records = topup_candidate_records if topup_candidate_records is not None else cf_p_records
    cf_p_primary_counts = Counter(
        record["primary_cwe"]
        for record in cf_p_records
        if record.get("primary_cwe") is not None
    )
    cf_p_languages = Counter(record.get("lang", "unknown") for record in cf_p_records)
    cf_p_unique_cves = sorted(
        {
            cve
            for record in cf_p_records
            for cve in record.get("cve_list", [record.get("cve")])
            if cve
        }
    )
    topup_vuln = sum(1 for record in topup_result.records if int(record.get("target", 0)) == 1)
    topup_benign = sum(1 for record in topup_result.records if int(record.get("target", 0)) == 0)
    candidate_primary_counts = Counter(
        record["primary_cwe"]
        for record in candidate_records
        if record.get("primary_cwe") is not None
    )
    surrogate_only_records = [
        record
        for record in candidate_records
        if record.get("primary_cwe") not in inventory.prime_cwe_set
    ]
    surrogate_primary_counts = Counter(
        record["primary_cwe"]
        for record in surrogate_only_records
        if record.get("primary_cwe") is not None
    )
    same_cwe_direct_count = sum(
        stats.get("cf_same_cwe_selected", 0) for stats in topup_result.per_cwe_stats.values()
    )
    same_major_replacement_count = sum(
        stats.get("cf_same_major_selected", 0) for stats in topup_result.per_cwe_stats.values()
    )
    per_anchor_replacement_cwe_distribution = {
        cwe: stats["same_major_replacement_cwe_counts"]
        for cwe, stats in sorted(topup_result.per_cwe_stats.items())
        if stats.get("same_major_replacement_cwe_counts")
    }

    return {
        "primevul": {
            "unique_primary_cwes": len(inventory.prime_cwe_set),
            "primary_cwe_counts": inventory.primary_cwe_counts,
            "benign_pool_size": len(inventory.benign_pool),
        },
        "cf_p": {
            "total_records": len(cf_p_records),
            "language_counts": dict(sorted(cf_p_languages.items())),
            "primary_cwe_counts": dict(sorted(cf_p_primary_counts.items())),
            "unique_cves": len(cf_p_unique_cves),
        },
        "topup_50": {
            "kept_cwes": topup_result.kept_cwes,
            "dropped_cwes": topup_result.dropped_cwes,
            "per_cwe": topup_result.per_cwe_stats,
            "candidate_pool_records": len(candidate_records),
            "candidate_primary_cwe_counts": dict(sorted(candidate_primary_counts.items())),
            "surrogate_only_records": len(surrogate_only_records),
            "surrogate_only_primary_cwe_counts": dict(sorted(surrogate_primary_counts.items())),
            "same_cwe_direct_count": same_cwe_direct_count,
            "same_major_replacement_count": same_major_replacement_count,
            "per_anchor_replacement_cwe_distribution": per_anchor_replacement_cwe_distribution,
            "anchors_dropped_after_same_major_search": topup_result.dropped_cwes,
            "vulnerable_count": topup_vuln,
            "benign_count": topup_benign,
            "benign_vul_ratio": (topup_benign / topup_vuln) if topup_vuln else None,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--primevul-train",
        type=Path,
        default=Path("data/primevul/primevul/primevul_train.jsonl"),
        help="Path to primevul_train.jsonl",
    )
    parser.add_argument(
        "--cvefixes-sql",
        type=Path,
        default=Path("data/CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz"),
        help="Path to CVEfixes SQL.gz dump",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/primevul/cf_p"),
        help="Directory for cf_p outputs",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed for reproducible sampling",
    )
    parser.add_argument(
        "--target-per-cwe",
        type=int,
        default=DEFAULT_TARGET_PER_CWE,
        help="Target vulnerable samples per CWE in cf_p_topup_50",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    primevul_records = list(iter_jsonl(args.primevul_train))
    inventory = build_primevul_inventory(
        primevul_records,
        per_cwe_cap=args.target_per_cwe,
        seed=args.seed,
    )
    covered_prime_cwes = {cwe for cwe in inventory.prime_cwe_set if cwe in CWE_TO_MIDDLE}
    relevant_majors = {
        major
        for cwe in covered_prime_cwes
        if (major := _known_major_for_cwe(cwe)) is not None
    }
    same_major_cwe_set = {
        cwe for cwe in CWE_TO_MIDDLE if _known_major_for_cwe(cwe) in relevant_majors
    }
    allowed_cwe_set = set(inventory.prime_cwe_set) | same_major_cwe_set

    cve_to_allowed_cwes = load_relevant_cwe_map(args.cvefixes_sql, allowed_cwe_set)
    topup_candidate_records = extract_cf_p_records(
        args.cvefixes_sql,
        cve_to_prime_cwes=cve_to_allowed_cwes,
        allowed_cwe_set=allowed_cwe_set,
        preferred_cwe_set=inventory.prime_cwe_set,
    )
    cf_p_records = [
        dict(record)
        for record in topup_candidate_records
        if record.get("primary_cwe") in inventory.prime_cwe_set
    ]
    topup_result = build_topup_dataset(
        inventory,
        topup_candidate_records,
        target_per_cwe=args.target_per_cwe,
        seed=args.seed,
    )
    stats = build_stats(
        inventory,
        cf_p_records,
        topup_result,
        topup_candidate_records=topup_candidate_records,
    )

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(cf_p_records, output_dir / "cf_p.jsonl")
    write_jsonl(topup_result.records, output_dir / "cf_p_topup_50.jsonl")
    (output_dir / "cf_p_stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Wrote {len(cf_p_records)} records to {output_dir / 'cf_p.jsonl'}")
    print(f"Wrote {len(topup_result.records)} records to {output_dir / 'cf_p_topup_50.jsonl'}")
    print(f"Wrote stats to {output_dir / 'cf_p_stats.json'}")
    print(
        "Kept",
        len(topup_result.kept_cwes),
        "CWEs; dropped",
        len(topup_result.dropped_cwes),
        "CWEs",
    )


if __name__ == "__main__":
    main()
