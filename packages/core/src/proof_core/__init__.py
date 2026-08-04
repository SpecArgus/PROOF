"""Deterministic analysis primitives shared by PROOF execution surfaces."""

from proof_core.input_closure import (
    InputClosure,
    InputClosureError,
    InputFile,
    InputLimits,
    InputManifest,
    InputResource,
    build_input_closure,
    build_input_manifest,
)

__all__ = [
    "InputClosure",
    "InputClosureError",
    "InputFile",
    "InputLimits",
    "InputManifest",
    "InputResource",
    "build_input_closure",
    "build_input_manifest",
]

__version__ = "0.1.0"
