# tests/test_cost_tracker.py
import pytest
import json
import tempfile
from pathlib import Path


def test_cost_tracker_creates_file():
    """CostTracker should create JSONL output file."""
    from evoprompt.utils.cost_tracker import CostTracker

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "cost.jsonl"
        tracker = CostTracker(output_path)

        tracker.start_sample("sample_1", "test_method")
        tracker.log_llm_call("gpt-4o", 100, 50, 1000.0)
        tracker.end_sample()

        assert output_path.exists()

        with open(output_path) as f:
            record = json.loads(f.readline())

        assert record["sample_id"] == "sample_1"
        assert record["method"] == "test_method"
        assert record["llm_calls"] == 1
        assert record["input_tokens"] == 100
        assert record["output_tokens"] == 50


def test_cost_tracker_accumulates_calls():
    """Multiple LLM calls should accumulate."""
    from evoprompt.utils.cost_tracker import CostTracker

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "cost.jsonl"
        tracker = CostTracker(output_path)

        tracker.start_sample("sample_1", "agent_method")
        tracker.log_llm_call("gpt-4o", 100, 50, 500.0)
        tracker.log_llm_call("gpt-4o", 150, 75, 600.0)
        tracker.log_retrieval_call(3, 50.0)
        record = tracker.end_sample()

        assert record.llm_calls == 2
        assert record.input_tokens == 250
        assert record.output_tokens == 125
        assert record.retrieval_calls == 1


def test_cost_tracker_records_time():
    """Total time should be tracked."""
    from evoprompt.utils.cost_tracker import CostTracker

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "cost.jsonl"
        tracker = CostTracker(output_path)

        tracker.start_sample("sample_1", "test")
        tracker.log_llm_call("gpt-4o", 100, 50, 1000.0)
        record = tracker.end_sample()

        assert record.time_ms >= 0  # At least 0
