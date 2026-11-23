from ....c99.signal import Raise, Signal
from ..systemv import ArmV5TBESysVModel


class ArmV5TBESysVRaise(Raise, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVSignal(Signal, ArmV5TBESysVModel):
    pass


__all__ = [
    "ArmV5TBESysVRaise",
    "ArmV5TBESysVSignal",
]
