from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV8MSysVModel


class ArmV8MSysVHtons(Htons, ArmV8MSysVModel):
    pass


class ArmV8MSysVNtohs(Ntohs, ArmV8MSysVModel):
    pass


class ArmV8MSysVHtonl(Htonl, ArmV8MSysVModel):
    pass


class ArmV8MSysVNtohl(Ntohl, ArmV8MSysVModel):
    pass


__all__ = ["ArmV8MSysVHtons", "ArmV8MSysVNtohs", "ArmV8MSysVHtonl", "ArmV8MSysVNtohl"]
