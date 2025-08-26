from ....c99.signal import Raise, Signal
from ..systemv import ArmHFSysVModel


class ArmHFSysVRaise(Raise, ArmHFSysVModel):
    pass


class ArmHFSysVSignal(Signal, ArmHFSysVModel):
    pass


__all__ = [
    "ArmHFSysVRaise",
    "ArmHFSysVSignal",
]
