from ....c99.signal import Raise, Signal
from ..systemv import PowerPCSysVModel


class PowerPCSysVRaise(Raise, PowerPCSysVModel):
    pass


class PowerPCSysVSignal(Signal, PowerPCSysVModel):
    pass


__all__ = [
    "PowerPCSysVRaise",
    "PowerPCSysVSignal",
]
