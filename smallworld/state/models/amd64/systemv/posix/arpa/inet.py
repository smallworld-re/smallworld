from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import AMD64SysVModel


class AMD64SysVHtons(Htons, AMD64SysVModel):
    pass


class AMD64SysVNtohs(Ntohs, AMD64SysVModel):
    pass


class AMD64SysVHtonl(Htonl, AMD64SysVModel):
    pass


class AMD64SysVNtohl(Ntohl, AMD64SysVModel):
    pass


__all__ = ["AMD64SysVHtons", "AMD64SysVNtohs", "AMD64SysVHtonl", "AMD64SysVNtohl"]
