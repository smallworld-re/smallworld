from ....c99.signal import Raise, Signal
from ..systemv import MIPSELSysVModel


class MIPSELSysVRaise(Raise, MIPSELSysVModel):
    pass


class MIPSELSysVSignal(Signal, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVRaise",
    "MIPSELSysVSignal",
]
