"""Core dataset interface."""

from abc import ABC, abstractmethod
from typing import List, Any, Optional

# This is a simple wrapper to maintain compatibility
from ..data.dataset import Sample, Dataset as BaseDataset

class Dataset(BaseDataset):
    """Core dataset interface for backward compatibility."""
    pass

__all__ = ["Dataset", "Sample"]