"""Pytest configuration and fixtures."""

import pytest
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import Mock

# Add src to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from evoprompt.llm.client import LLMClient
from evoprompt.core.evaluator import Evaluator
from evoprompt.data.dataset import Dataset
from evoprompt.metrics.base import Metric


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def mock_llm_client():
    """Mock LLM client for testing."""
    client = Mock(spec=LLMClient)
    client.generate.return_value = "Generated response"
    return client


@pytest.fixture
def mock_metric():
    """Mock metric for testing."""
    metric = Mock(spec=Metric)
    metric.compute.return_value = 0.85
    return metric


@pytest.fixture
def mock_dataset():
    """Mock dataset for testing."""
    dataset = Mock(spec=Dataset)
    
    class MockSample:
        def __init__(self, input_text, target):
            self.input_text = input_text
            self.target = target
            self.metadata = {}
    
    dataset.get_samples.return_value = [
        MockSample("What is 2+2?", "4"),
        MockSample("What is 3+3?", "6"),
    ]
    return dataset


@pytest.fixture
def mock_evaluator(mock_dataset, mock_metric, mock_llm_client):
    """Mock evaluator for testing."""
    return Evaluator(
        dataset=mock_dataset,
        metric=mock_metric,
        llm_client=mock_llm_client
    )


@pytest.fixture
def sample_prompts():
    """Sample prompts for testing."""
    return [
        "Solve this math problem: {input}",
        "Calculate the result: {input}",
        "What is the answer to: {input}",
    ]