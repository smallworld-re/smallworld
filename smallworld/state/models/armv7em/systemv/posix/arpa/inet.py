from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV7EMSysVModel


class ArmV7EMSysVHtons(Htons, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVNtohs(Ntohs, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVHtonl(Htonl, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVNtohl(Ntohl, ArmV7EMSysVModel):
    pass


__all__ = [
    "ArmV7EMSysVHtons",
    "ArmV7EMSysVNtohs",
    "ArmV7EMSysVHtonl",
    "ArmV7EMSysVNtohl",
]
