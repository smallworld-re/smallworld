from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import MIPS64SysVModel


class MIPS64SysVHtons(Htons, MIPS64SysVModel):
    pass


class MIPS64SysVNtohs(Ntohs, MIPS64SysVModel):
    pass


class MIPS64SysVHtonl(Htonl, MIPS64SysVModel):
    pass


class MIPS64SysVNtohl(Ntohl, MIPS64SysVModel):
    pass


__all__ = ["MIPS64SysVHtons", "MIPS64SysVNtohs", "MIPS64SysVHtonl", "MIPS64SysVNtohl"]
