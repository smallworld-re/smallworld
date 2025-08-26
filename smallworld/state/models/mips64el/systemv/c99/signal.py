from ....c99.signal import Raise, Signal
from ..systemv import MIPS64ELSysVModel


class MIPS64ELSysVRaise(Raise, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVSignal(Signal, MIPS64ELSysVModel):
    pass


__all__ = [
    "MIPS64ELSysVRaise",
    "MIPS64ELSysVSignal",
]
