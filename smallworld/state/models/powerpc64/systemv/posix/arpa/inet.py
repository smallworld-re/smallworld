from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import PowerPC64SysVModel


class PowerPC64SysVHtons(Htons, PowerPC64SysVModel):
    pass


class PowerPC64SysVNtohs(Ntohs, PowerPC64SysVModel):
    pass


class PowerPC64SysVHtonl(Htonl, PowerPC64SysVModel):
    pass


class PowerPC64SysVNtohl(Ntohl, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVHtons",
    "PowerPC64SysVNtohs",
    "PowerPC64SysVHtonl",
    "PowerPC64SysVNtohl",
]
