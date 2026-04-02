"""Meta-learning module for prompt optimization.

Provides error accumulation and prompt tuning capabilities for
continuous improvement of hierarchical vulnerability detection.
"""

from .error_accumulator import (
    ClassificationError,
    ErrorPattern,
    ErrorAccumulator,
)
from .prompt_tuner import (
    TuningResult,
    MetaLearningPromptTuner,
)

__all__ = [
    "ClassificationError",
    "ErrorPattern",
    "ErrorAccumulator",
    "TuningResult",
    "MetaLearningPromptTuner",
]
