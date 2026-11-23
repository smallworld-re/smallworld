from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV6KSysVModel


class ArmV6KSysVHtons(Htons, ArmV6KSysVModel):
    pass


class ArmV6KSysVNtohs(Ntohs, ArmV6KSysVModel):
    pass


class ArmV6KSysVHtonl(Htonl, ArmV6KSysVModel):
    pass


class ArmV6KSysVNtohl(Ntohl, ArmV6KSysVModel):
    pass


__all__ = ["ArmV6KSysVHtons", "ArmV6KSysVNtohs", "ArmV6KSysVHtonl", "ArmV6KSysVNtohl"]
