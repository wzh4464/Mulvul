"""Tests for environment-loading helpers."""

from __future__ import annotations

import os
from pathlib import Path

from mulvul.llm.helpers import load_env_vars


def test_load_env_vars_does_not_override_existing_environment(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    env_path = Path(".env")
    env_path.write_text(
        "\n".join(
            [
                "API_BASE_URL=https://openrouter.ai/api/v1",
                "MODEL_NAME=openai/gpt-5.4",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("API_BASE_URL", "https://yunwu.ai/v1")
    monkeypatch.setenv("MODEL_NAME", "gpt-5.4")

    load_env_vars()

    assert os.getenv("API_BASE_URL") == "https://yunwu.ai/v1"
    assert os.getenv("MODEL_NAME") == "gpt-5.4"


def test_load_env_vars_populates_missing_environment(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    env_path = Path(".env")
    env_path.write_text(
        "\n".join(
            [
                "API_BASE_URL=https://yunwu.ai/v1",
                "MODEL_NAME=gpt-5.4",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("API_BASE_URL", raising=False)
    monkeypatch.delenv("MODEL_NAME", raising=False)

    load_env_vars()

    assert os.getenv("API_BASE_URL") == "https://yunwu.ai/v1"
    assert os.getenv("MODEL_NAME") == "gpt-5.4"
