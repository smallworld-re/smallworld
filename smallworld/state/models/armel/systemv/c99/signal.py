from ....c99.signal import Raise, Signal
from ..systemv import ArmELSysVModel


class ArmELSysVRaise(Raise, ArmELSysVModel):
    pass


class ArmELSysVSignal(Signal, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVRaise",
    "ArmELSysVSignal",
]
