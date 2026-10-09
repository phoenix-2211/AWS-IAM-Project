"""Backward compatibility shim for Stage 2 Path Discovery."""

from engine3.s2_path_discovery import (
    CandidatePath,
    PathHop,
    Stage2DiscoveryResult,
    Stage2PathDiscovery,
    Stage2PathFinder,
)

__all__ = [
    "PathHop",
    "CandidatePath",
    "Stage2DiscoveryResult",
    "Stage2PathFinder",
    "Stage2PathDiscovery",
]
