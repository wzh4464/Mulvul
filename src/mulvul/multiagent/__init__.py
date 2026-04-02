"""Multi-agent framework for collaborative prompt evolution."""

from .agents import (
    DetectionAgent,
    MetaAgent,
    AgentRole,
)
from .coordinator import (
    MultiAgentCoordinator,
    CoordinationStrategy,
)

__all__ = [
    "DetectionAgent",
    "MetaAgent",
    "AgentRole",
    "MultiAgentCoordinator",
    "CoordinationStrategy",
]
