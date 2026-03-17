from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import MIPSELSysVModel


class MIPSELSysVHtons(Htons, MIPSELSysVModel):
    pass


class MIPSELSysVNtohs(Ntohs, MIPSELSysVModel):
    pass


class MIPSELSysVHtonl(Htonl, MIPSELSysVModel):
    pass


class MIPSELSysVNtohl(Ntohl, MIPSELSysVModel):
    pass


__all__ = ["MIPSELSysVHtons", "MIPSELSysVNtohs", "MIPSELSysVHtonl", "MIPSELSysVNtohl"]
