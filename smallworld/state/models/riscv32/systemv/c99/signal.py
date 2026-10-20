from ....c99.signal import Raise, Signal
from ..systemv import RiscV32SysVModel


class RiscV32SysVRaise(Raise, RiscV32SysVModel):
    pass


class RiscV32SysVSignal(Signal, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVRaise",
    "RiscV32SysVSignal",
]
