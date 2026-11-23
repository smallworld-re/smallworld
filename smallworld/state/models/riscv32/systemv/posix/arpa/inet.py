from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import RiscV32SysVModel


class RiscV32SysVHtons(Htons, RiscV32SysVModel):
    pass


class RiscV32SysVNtohs(Ntohs, RiscV32SysVModel):
    pass


class RiscV32SysVHtonl(Htonl, RiscV32SysVModel):
    pass


class RiscV32SysVNtohl(Ntohl, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVHtons",
    "RiscV32SysVNtohs",
    "RiscV32SysVHtonl",
    "RiscV32SysVNtohl",
]
