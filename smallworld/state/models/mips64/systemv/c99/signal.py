from ....c99.signal import Raise, Signal
from ..systemv import MIPS64SysVModel


class MIPS64SysVRaise(Raise, MIPS64SysVModel):
    pass


class MIPS64SysVSignal(Signal, MIPS64SysVModel):
    pass


__all__ = [
    "MIPS64SysVRaise",
    "MIPS64SysVSignal",
]
