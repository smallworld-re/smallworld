# Importing the concrete subclasses for the side effect of registering them with StyxMachineDef.for_platform().
from . import armel  # noqa: F401
from . import armhf  # noqa: F401
from . import powerpc  # noqa: F401
from .machdef import StyxMachineDef

__all__ = ["StyxMachineDef"]
