from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import M68KSysVModel


class M68KSysVHtons(Htons, M68KSysVModel):
    pass


class M68KSysVNtohs(Ntohs, M68KSysVModel):
    pass


class M68KSysVHtonl(Htonl, M68KSysVModel):
    pass


class M68KSysVNtohl(Ntohl, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVHtons",
    "M68KSysVNtohs",
    "M68KSysVHtonl",
    "M68KSysVNtohl",
]
