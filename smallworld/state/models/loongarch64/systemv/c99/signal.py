from ....c99.signal import Raise, Signal
from ..systemv import LoongArch64SysVModel


class LoongArch64SysVRaise(Raise, LoongArch64SysVModel):
    pass


class LoongArch64SysVSignal(Signal, LoongArch64SysVModel):
    pass


__all__ = [
    "LoongArch64SysVRaise",
    "LoongArch64SysVSignal",
]
