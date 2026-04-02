"""Tracing utilities for detailed prompt evolution and sample-level analysis.

Default: enabled. Use release mode to disable all tracing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional
import json
import os


def _env_truthy(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def trace_enabled_from_env(default: bool = True) -> bool:
    """Determine trace enablement from environment variables.

    EVOPROMPT_RELEASE=1 disables tracing.
    EVOPROMPT_TRACE=0 disables tracing.
    """
    if _env_truthy(os.getenv("EVOPROMPT_RELEASE")):
        return False
    trace_override = os.getenv("EVOPROMPT_TRACE")
    if trace_override is not None:
        return _env_truthy(trace_override)
    return default


def compute_text_hash(text: str) -> str:
    """Compute a stable short hash for text."""
    if text is None:
        text = ""
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


@dataclass
class TraceConfig:
    """Configuration for trace logging."""

    enabled: bool = True
    base_dir: Optional[Path] = None
    experiment_id: Optional[str] = None
    store_code: bool = True
    store_prompts: bool = True
    store_filled_prompts: bool = True
    store_raw_responses: bool = True
    store_rag_context: bool = True


class TraceManager:
    """Structured trace logger for prompt evolution and sample-level events."""

    def __init__(self, config: TraceConfig):
        self.config = config
        self.enabled = bool(config.enabled)

        if not self.enabled:
            self.base_dir = None
            self.trace_dir = None
            self.prompts_dir = None
            return

        if config.base_dir is None:
            raise ValueError("TraceConfig.base_dir must be set when tracing is enabled")

        self.base_dir = Path(config.base_dir)
        self.trace_dir = self.base_dir / "trace"
        self.prompts_dir = self.base_dir / "prompts"

        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self.prompts_dir.mkdir(parents=True, exist_ok=True)

        self._evolution_file = self.trace_dir / "evolution.jsonl"
        self._samples_file = self.trace_dir / "samples.jsonl"
        self._events_file = self.trace_dir / "events.jsonl"

    def log_event(self, event_type: str, payload: Dict[str, Any]):
        """Log a generic event to events.jsonl."""
        if not self.enabled:
            return
        record = self._wrap_record(event_type, payload)
        self._append_jsonl(self._events_file, record)

    def log_prompt_update(self, payload: Dict[str, Any]):
        """Log a prompt update event."""
        if not self.enabled:
            return
        record = self._wrap_record("prompt_update", payload)
        self._append_jsonl(self._evolution_file, record)

    def log_sample_trace(self, payload: Dict[str, Any]):
        """Log a sample-level trace event."""
        if not self.enabled:
            return
        record = self._wrap_record("sample_trace", payload)
        self._append_jsonl(self._samples_file, record)

    def save_prompt_snapshot(self, name: str, prompt: str, metadata: Optional[Dict[str, Any]] = None):
        """Save a full prompt snapshot with metadata."""
        if not self.enabled or not self.config.store_prompts:
            return
        meta = metadata or {}
        snapshot = {
            "name": name,
            "prompt": prompt,
            "metadata": meta,
            "timestamp": datetime.now().isoformat(),
        }
        json_path = self.prompts_dir / f"{name}.json"
        txt_path = self.prompts_dir / f"{name}.txt"
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, ensure_ascii=False, indent=2)
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(prompt)
        except Exception:
            # Do not fail main flow on trace errors
            pass

    def _wrap_record(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        record = {
            "event": event_type,
            "timestamp": datetime.now().isoformat(),
        }
        if self.config.experiment_id:
            record["experiment_id"] = self.config.experiment_id
        record.update(payload)
        return record

    @staticmethod
    def _append_jsonl(path: Path, record: Dict[str, Any]):
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            # Do not fail main flow on trace errors
            pass
