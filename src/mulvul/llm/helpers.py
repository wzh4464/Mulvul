"""Shared helpers for LLM clients and runtime configuration."""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_TASK_TRUNCATION_STRATEGY = "first_paragraph"
DEFAULT_LLM_CACHE_ROOT = ".cache/mulvul/llm"


def load_env_vars() -> None:
    """Load environment variables from the first available .env file."""
    possible_paths = [
        Path(__file__).parent.parent.parent / ".env",
        Path.cwd() / ".env",
        Path(__file__).parent.parent.parent.parent / ".env",
    ]

    for env_path in possible_paths:
        if not env_path.exists():
            continue

        logger.debug("Loading .env from: %s", env_path)
        with env_path.open("r", encoding="utf-8") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                normalized_key = key.strip()
                if normalized_key not in os.environ:
                    os.environ[normalized_key] = value.strip()
        return

    logger.warning("No .env file found in any expected location")


def get_env_int(name: str, default: int) -> int:
    """Read an integer environment variable with fallback."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning("Invalid integer for %s: %s; using %s", name, value, default)
        return default


def get_env_float(name: str, default: float) -> float:
    """Read a float environment variable with fallback."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        logger.warning("Invalid float for %s: %s; using %s", name, value, default)
        return default


def get_env_bool(name: str, default: bool) -> bool:
    """Read a boolean environment variable with fallback."""
    value = os.getenv(name)
    if value is None:
        return default

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False

    logger.warning("Invalid boolean for %s: %s; using %s", name, value, default)
    return default


def resolve_llm_cache_dir(
    *,
    namespace: str = "default",
    cache_dir: str | None = None,
) -> str:
    """Resolve the on-disk cache directory for LLM responses."""
    if cache_dir:
        return str(Path(cache_dir))

    root = Path(os.getenv("MULVUL_LLM_CACHE_DIR", DEFAULT_LLM_CACHE_ROOT))
    if namespace:
        root = root / namespace
    return str(root)


def task_truncation_strategy(default: str = DEFAULT_TASK_TRUNCATION_STRATEGY) -> str:
    """Return the configured task-response truncation strategy."""
    return os.getenv("MULVUL_TASK_TRUNCATION_STRATEGY", default)


def truncate_task_response(
    response: str,
    *,
    strategy: str | None = None,
) -> str:
    """Apply a configurable post-processing strategy to task responses."""
    resolved = (strategy or task_truncation_strategy()).strip().lower()

    if resolved in {"", "none", "disabled"}:
        return response

    stripped = response.strip()
    if not stripped:
        return stripped

    if resolved == "first_nonempty_line":
        for line in response.splitlines():
            candidate = line.strip()
            if candidate:
                return candidate
        return stripped

    if resolved != "first_paragraph":
        logger.warning(
            "Unknown task truncation strategy %s; falling back to first_paragraph",
            resolved,
        )

    for paragraph in response.split("\n\n"):
        candidate = paragraph.strip()
        if candidate:
            return candidate
    return stripped
