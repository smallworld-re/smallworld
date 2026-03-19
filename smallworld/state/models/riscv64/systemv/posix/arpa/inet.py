from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import RiscV64SysVModel


class RiscV64SysVHtons(Htons, RiscV64SysVModel):
    pass


class RiscV64SysVNtohs(Ntohs, RiscV64SysVModel):
    pass


class RiscV64SysVHtonl(Htonl, RiscV64SysVModel):
    pass


class RiscV64SysVNtohl(Ntohl, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVHtons",
    "RiscV64SysVNtohs",
    "RiscV64SysVHtonl",
    "RiscV64SysVNtohl",
]
