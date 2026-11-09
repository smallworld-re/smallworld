from ....c99.signal import Raise, Signal
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVRaise(Raise, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSignal(Signal, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVRaise",
    "MicroMIPSELSysVSignal",
]
