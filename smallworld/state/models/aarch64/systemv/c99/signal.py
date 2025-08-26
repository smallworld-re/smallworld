from ....c99.signal import Raise, Signal
from ..systemv import AArch64SysVModel


class AArch64SysVRaise(Raise, AArch64SysVModel):
    pass


class AArch64SysVSignal(Signal, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVRaise",
    "AArch64SysVSignal",
]
