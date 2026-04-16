"""Backward-compatible alias for the legacy ``mulvul.data.sampling`` module."""

from .sampler import BalancedSampler, sample_primevul_1percent

__all__ = ["BalancedSampler", "sample_primevul_1percent"]
