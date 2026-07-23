from .triton import TritonEmulationError, TritonEmulator

# The symbolic emulator additionally needs Triton's Z3 bridge (``tritonToZ3``).
# A Triton build without the Z3 interface (or a missing ``z3`` module) leaves the
# concrete emulator fully usable while omitting the symbolic one.
try:
    from .symbolic import TritonSymbolicEmulator  # noqa: F401

    __all__ = ["TritonEmulator", "TritonSymbolicEmulator", "TritonEmulationError"]
except ImportError:  # pragma: no cover - depends on the Triton build
    __all__ = ["TritonEmulator", "TritonEmulationError"]
