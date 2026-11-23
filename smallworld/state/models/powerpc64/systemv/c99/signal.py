from ....c99.signal import Raise, Signal
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVRaise(Raise, PowerPC64SysVModel):
    pass


class PowerPC64SysVSignal(Signal, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVRaise",
    "PowerPC64SysVSignal",
]
