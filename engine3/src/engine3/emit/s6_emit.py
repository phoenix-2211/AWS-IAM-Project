"""Backward compatibility shim for Stage 8 Output Packaging."""

from engine3.s8_output import (
    Stage6Assembler,
    Stage8Output,
    Stage8OutputAssembler,
)

__all__ = [
    "Stage6Assembler",
    "Stage8OutputAssembler",
    "Stage8Output",
]
