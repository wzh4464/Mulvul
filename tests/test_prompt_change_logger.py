"""Tests for PromptChangeLogger."""

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Import detectors first so that detectors.__init__ -> hierarchical_coordinator
# -> meta.prompt_tuner resolves before meta.__init__ is triggered.
from evoprompt.detectors.parallel_hierarchical_detector import HierarchicalPromptSet  # noqa: F401
from evoprompt.meta.prompt_tuner import MetaLearningPromptTuner
from evoprompt.multiagent.coordinator import MultiAgentCoordinator, CoordinatorConfig
from evoprompt.core.prompt_change_logger import PromptChangeLogger, PromptChangeRecord
from evoprompt.utils.trace import compute_text_hash


@pytest.fixture
def log_dir(tmp_path):
    return tmp_path / "test_output"


@pytest.fixture
def logger(log_dir):
    return PromptChangeLogger(output_dir=log_dir)


def test_log_change_creates_file(logger, log_dir):
    """Logging a change creates the JSONL file."""
    logger.log_change(
        operation="meta_improve",
        prompt_before="old prompt",
        prompt_after="new prompt",
    )
    assert logger.log_file.exists()
    lines = logger.log_file.read_text().strip().splitlines()
    assert len(lines) == 1


def test_record_schema(logger):
    """All required fields are present in the record."""
    logger.log_change(
        operation="meta_mutate",
        prompt_before="before",
        prompt_after="after",
        generation=3,
        layer=2,
        category="Buffer Errors",
        trigger_reason="evolutionary_operator",
        context={"key": "value"},
        metrics_before={"accuracy": 0.5},
        metrics_after={"accuracy": 0.7},
    )
    line = logger.log_file.read_text().strip()
    rec = json.loads(line)

    required_fields = [
        "timestamp", "operation", "generation", "layer", "category",
        "prompt_before", "prompt_after", "prompt_hash_before",
        "prompt_hash_after", "trigger_reason", "context",
        "metrics_before", "metrics_after", "length_change",
    ]
    for field in required_fields:
        assert field in rec, f"Missing field: {field}"


def test_hashes_computed(logger):
    """prompt_hash_before and prompt_hash_after are correctly populated."""
    before = "analyze this code for vulnerabilities"
    after = "carefully analyze this code for buffer overflow vulnerabilities"
    logger.log_change(operation="meta_improve", prompt_before=before, prompt_after=after)

    rec = json.loads(logger.log_file.read_text().strip())
    assert rec["prompt_hash_before"] == compute_text_hash(before)
    assert rec["prompt_hash_after"] == compute_text_hash(after)


def test_length_change_computed(logger):
    """length_change reflects the difference in prompt lengths."""
    before = "short"
    after = "much longer prompt text"
    logger.log_change(operation="meta_tune", prompt_before=before, prompt_after=after)

    rec = json.loads(logger.log_file.read_text().strip())
    assert rec["length_change"] == len(after) - len(before)


def test_thread_safe_concurrent_writes(log_dir):
    """Concurrent writes from multiple threads don't corrupt the log."""
    pcl = PromptChangeLogger(output_dir=log_dir)
    n_threads = 10
    writes_per_thread = 20

    def writer(thread_id):
        for i in range(writes_per_thread):
            pcl.log_change(
                operation=f"op_{thread_id}",
                prompt_before=f"before_{thread_id}_{i}",
                prompt_after=f"after_{thread_id}_{i}",
                generation=i,
            )

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = pcl.log_file.read_text().strip().splitlines()
    assert len(lines) == n_threads * writes_per_thread

    # Every line should be valid JSON
    for line in lines:
        json.loads(line)


def test_get_summary_counts(logger):
    """get_summary correctly counts by operation type."""
    logger.log_change(operation="meta_improve", prompt_before="a", prompt_after="b")
    logger.log_change(operation="meta_improve", prompt_before="a", prompt_after="c")
    logger.log_change(operation="meta_tune", prompt_before="a", prompt_after="d")

    summary = logger.get_summary()
    assert summary["total_changes"] == 3
    assert summary["by_operation"]["meta_improve"] == 2
    assert summary["by_operation"]["meta_tune"] == 1


def test_get_summary_empty(log_dir):
    """get_summary on a fresh logger with no writes returns zeros."""
    pcl = PromptChangeLogger(output_dir=log_dir)
    summary = pcl.get_summary()
    assert summary["total_changes"] == 0
    assert summary["by_operation"] == {}


def test_backward_compatible_coordinator_none_logger():
    """MultiAgentCoordinator works with prompt_change_logger=None (default)."""
    coord = MultiAgentCoordinator(
        detection_agent=MagicMock(),
        meta_agent=MagicMock(),
        config=CoordinatorConfig(),
    )
    assert coord.prompt_change_logger is None


def test_backward_compatible_tuner_none_logger():
    """MetaLearningPromptTuner works with prompt_change_logger=None (default)."""
    tuner = MetaLearningPromptTuner(
        llm_client=MagicMock(),
    )
    assert tuner.prompt_change_logger is None
