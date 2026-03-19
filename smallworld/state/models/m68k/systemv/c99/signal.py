from ....c99.signal import Raise, Signal
from ..systemv import M68KSysVModel


class M68KSysVRaise(Raise, M68KSysVModel):
    pass


class M68KSysVSignal(Signal, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVRaise",
    "M68KSysVSignal",
]
