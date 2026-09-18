from ....c99.math import Fabs
from ..systemv import PowerPCSysVModel


class PowerPCSysVFabs(Fabs, PowerPCSysVModel):
    pass


__all__ = ["PowerPCSysVFabs"]
