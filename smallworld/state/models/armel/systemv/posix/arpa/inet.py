from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmELSysVModel


class ArmELSysVHtons(Htons, ArmELSysVModel):
    pass


class ArmELSysVNtohs(Ntohs, ArmELSysVModel):
    pass


class ArmELSysVHtonl(Htonl, ArmELSysVModel):
    pass


class ArmELSysVNtohl(Ntohl, ArmELSysVModel):
    pass


__all__ = ["ArmELSysVHtons", "ArmELSysVNtohs", "ArmELSysVHtonl", "ArmELSysVNtohl"]
