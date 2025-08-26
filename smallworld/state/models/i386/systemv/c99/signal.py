from ....c99.signal import Raise, Signal
from ..systemv import I386SysVModel


class I386SysVRaise(Raise, I386SysVModel):
    pass


class I386SysVSignal(Signal, I386SysVModel):
    pass


__all__ = [
    "I386SysVRaise",
    "I386SysVSignal",
]
