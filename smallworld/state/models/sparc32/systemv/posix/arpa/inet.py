from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import SPARC32SysVModel


class SPARC32SysVHtons(Htons, SPARC32SysVModel):
    pass


class SPARC32SysVNtohs(Ntohs, SPARC32SysVModel):
    pass


class SPARC32SysVHtonl(Htonl, SPARC32SysVModel):
    pass


class SPARC32SysVNtohl(Ntohl, SPARC32SysVModel):
    pass


__all__ = [
    "SPARC32SysVHtons",
    "SPARC32SysVNtohs",
    "SPARC32SysVHtonl",
    "SPARC32SysVNtohl",
]
