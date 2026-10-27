from ....c99.signal import Raise, Signal
from ..systemv import ArmV4TBESysVModel


class ArmV4TBESysVRaise(Raise, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVSignal(Signal, ArmV4TBESysVModel):
    pass


__all__ = [
    "ArmV4TBESysVRaise",
    "ArmV4TBESysVSignal",
]
