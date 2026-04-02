"""Always-on prompt change logger.

Records every prompt mutation (evolution, meta-learning, tuning) to a JSONL
file regardless of release mode.  This provides a complete audit trail of
how prompts evolved during training.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..utils.trace import compute_text_hash


@dataclass
class PromptChangeRecord:
    """A single prompt change event."""

    timestamp: str
    operation: str  # "meta_improve" | "meta_crossover" | "meta_mutate" | "meta_tune"
    generation: int
    layer: Optional[int]
    category: Optional[str]
    prompt_before: str
    prompt_after: str
    prompt_hash_before: str
    prompt_hash_after: str
    trigger_reason: str  # "evolutionary_operator" | "error_pattern" | ...
    context: Dict[str, Any]
    metrics_before: Optional[Dict[str, Any]]
    metrics_after: Optional[Dict[str, Any]]
    length_change: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PromptChangeLogger:
    """Thread-safe, always-on logger that appends prompt changes to JSONL."""

    def __init__(self, output_dir: Path) -> None:
        self.log_file = Path(output_dir) / "prompt_changes.jsonl"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log_change(
        self,
        operation: str,
        prompt_before: str,
        prompt_after: str,
        generation: int = 0,
        layer: Optional[int] = None,
        category: Optional[str] = None,
        trigger_reason: str = "",
        context: Optional[Dict[str, Any]] = None,
        metrics_before: Optional[Dict[str, Any]] = None,
        metrics_after: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append a prompt change record to the JSONL log."""
        record = PromptChangeRecord(
            timestamp=datetime.now().isoformat(),
            operation=operation,
            generation=generation,
            layer=layer,
            category=category,
            prompt_before=prompt_before,
            prompt_after=prompt_after,
            prompt_hash_before=compute_text_hash(prompt_before),
            prompt_hash_after=compute_text_hash(prompt_after),
            trigger_reason=trigger_reason,
            context=context or {},
            metrics_before=metrics_before,
            metrics_after=metrics_after,
            length_change=len(prompt_after) - len(prompt_before),
        )
        with self._lock:
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record.to_dict(), ensure_ascii=False) + "\n")
            except Exception:
                # Never break the main training loop
                pass

    def get_summary(self) -> Dict[str, Any]:
        """Read the log and return counts by operation type."""
        counts: Dict[str, int] = {}
        total = 0
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    op = rec.get("operation", "unknown")
                    counts[op] = counts.get(op, 0) + 1
                    total += 1
        except FileNotFoundError:
            pass
        return {"total_changes": total, "by_operation": counts}
