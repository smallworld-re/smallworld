# Import the concrete subclasses for the side effect of registering them with
# TritonMachineDef.for_platform() (via utils.find_subclass over __subclasses__).
from . import aarch64  # noqa: F401
from . import amd64  # noqa: F401
from . import arm  # noqa: F401
from . import i386  # noqa: F401
from . import riscv64  # noqa: F401
from .machdef import TritonMachineDef

__all__ = ["TritonMachineDef"]
