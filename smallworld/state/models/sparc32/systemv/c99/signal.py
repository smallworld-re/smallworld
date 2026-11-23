from ....c99.signal import Raise, Signal
from ..systemv import SPARC32SysVModel


class SPARC32SysVRaise(Raise, SPARC32SysVModel):
    pass


class SPARC32SysVSignal(Signal, SPARC32SysVModel):
    pass


__all__ = [
    "SPARC32SysVRaise",
    "SPARC32SysVSignal",
]
