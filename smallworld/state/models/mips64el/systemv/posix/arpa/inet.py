from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import MIPS64ELSysVModel


class MIPS64ELSysVHtons(Htons, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVNtohs(Ntohs, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVHtonl(Htonl, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVNtohl(Ntohl, MIPS64ELSysVModel):
    pass


__all__ = [
    "MIPS64ELSysVHtons",
    "MIPS64ELSysVNtohs",
    "MIPS64ELSysVHtonl",
    "MIPS64ELSysVNtohl",
]
