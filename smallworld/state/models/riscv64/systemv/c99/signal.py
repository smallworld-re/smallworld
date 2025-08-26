from ....c99.signal import Raise, Signal
from ..systemv import RiscV64SysVModel


class RiscV64SysVRaise(Raise, RiscV64SysVModel):
    pass


class RiscV64SysVSignal(Signal, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVRaise",
    "RiscV64SysVSignal",
]
