"""Backward compatibility shim for Stage 0 Intake."""

from engine3.s0_intake import (
    Stage0Intake,
    Stage0IntakeResult,
    Stage0LoadResult,
    Stage0Loader,
    StructuredError,
)

__all__ = [
    "StructuredError",
    "Stage0LoadResult",
    "Stage0IntakeResult",
    "Stage0Loader",
    "Stage0Intake",
]
