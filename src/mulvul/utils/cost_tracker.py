"""Cost tracking for LLM and retrieval calls."""

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class CostRecord:
    """Record of costs for a single sample."""
    sample_id: str
    method: str
    llm_calls: int = 0
    retrieval_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    time_ms: float = 0.0
    llm_call_details: List[Dict] = field(default_factory=list)
    retrieval_call_details: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


class CostTracker:
    """Track costs for LLM and retrieval calls.

    Usage:
        tracker = CostTracker(Path("cost.jsonl"))
        tracker.start_sample("sample_1", "method_name")
        tracker.log_llm_call("gpt-4o", 100, 50, 1000.0)
        tracker.log_retrieval_call(3, 50.0)
        tracker.end_sample()
    """

    def __init__(self, output_path: Path):
        """Initialize cost tracker.

        Args:
            output_path: Path to JSONL output file
        """
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._current: Optional[CostRecord] = None
        self._start_time: Optional[float] = None

    def start_sample(self, sample_id: str, method: str) -> None:
        """Begin tracking a new sample."""
        self._current = CostRecord(sample_id=str(sample_id), method=method)
        self._start_time = time.perf_counter()

    def log_llm_call(
        self,
        model: str,
        in_tokens: int,
        out_tokens: int,
        time_ms: float
    ) -> None:
        """Log a single LLM call."""
        if self._current is None:
            raise RuntimeError("Must call start_sample() before log_llm_call()")

        self._current.llm_calls += 1
        self._current.input_tokens += in_tokens
        self._current.output_tokens += out_tokens
        self._current.llm_call_details.append({
            "model": model,
            "in_tokens": in_tokens,
            "out_tokens": out_tokens,
            "time_ms": time_ms
        })

    def log_retrieval_call(self, top_k: int, time_ms: float) -> None:
        """Log a retrieval operation."""
        if self._current is None:
            raise RuntimeError("Must call start_sample() before log_retrieval_call()")

        self._current.retrieval_calls += 1
        self._current.retrieval_call_details.append({
            "top_k": top_k,
            "time_ms": time_ms
        })

    def end_sample(self) -> CostRecord:
        """Finalize current sample and write to file."""
        if self._current is None:
            raise RuntimeError("Must call start_sample() before end_sample()")

        # Calculate total time
        if self._start_time is not None:
            self._current.time_ms = (time.perf_counter() - self._start_time) * 1000

        # Write to JSONL
        with open(self.output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(self._current.to_dict()) + "\n")

        record = self._current
        self._current = None
        self._start_time = None

        return record
