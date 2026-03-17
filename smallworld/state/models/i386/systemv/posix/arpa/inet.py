from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import I386SysVModel


class I386SysVHtons(Htons, I386SysVModel):
    pass


class I386SysVNtohs(Ntohs, I386SysVModel):
    pass


class I386SysVHtonl(Htonl, I386SysVModel):
    pass


class I386SysVNtohl(Ntohl, I386SysVModel):
    pass


__all__ = ["I386SysVHtons", "I386SysVNtohs", "I386SysVHtonl", "I386SysVNtohl"]
