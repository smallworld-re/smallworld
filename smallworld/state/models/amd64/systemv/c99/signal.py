from ....c99.signal import Raise, Signal
from ..systemv import AMD64SysVModel


class AMD64SysVRaise(Raise, AMD64SysVModel):
    pass


class AMD64SysVSignal(Signal, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVRaise",
    "AMD64SysVSignal",
]
