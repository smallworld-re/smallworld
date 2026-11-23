from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVHtons(Htons, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVNtohs(Ntohs, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVHtonl(Htonl, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVNtohl(Ntohl, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVHtons",
    "MicroMIPSELSysVNtohs",
    "MicroMIPSELSysVHtonl",
    "MicroMIPSELSysVNtohl",
]
