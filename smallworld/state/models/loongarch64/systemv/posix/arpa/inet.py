from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import LoongArch64SysVModel


class LoongArch64SysVHtons(Htons, LoongArch64SysVModel):
    pass


class LoongArch64SysVNtohs(Ntohs, LoongArch64SysVModel):
    pass


class LoongArch64SysVHtonl(Htonl, LoongArch64SysVModel):
    pass


class LoongArch64SysVNtohl(Ntohl, LoongArch64SysVModel):
    pass


__all__ = [
    "LoongArch64SysVHtons",
    "LoongArch64SysVNtohs",
    "LoongArch64SysVHtonl",
    "LoongArch64SysVNtohl",
]
