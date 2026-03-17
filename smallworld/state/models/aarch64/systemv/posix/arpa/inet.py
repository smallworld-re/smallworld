from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import AArch64SysVModel


class AArch64SysVHtons(Htons, AArch64SysVModel):
    pass


class AArch64SysVNtohs(Ntohs, AArch64SysVModel):
    pass


class AArch64SysVHtonl(Htonl, AArch64SysVModel):
    pass


class AArch64SysVNtohl(Ntohl, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVHtons",
    "AArch64SysVNtohs",
    "AArch64SysVHtonl",
    "AArch64SysVNtohl",
]
