from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV5TSysVModel


class ArmV5TSysVHtons(Htons, ArmV5TSysVModel):
    pass


class ArmV5TSysVNtohs(Ntohs, ArmV5TSysVModel):
    pass


class ArmV5TSysVHtonl(Htonl, ArmV5TSysVModel):
    pass


class ArmV5TSysVNtohl(Ntohl, ArmV5TSysVModel):
    pass


__all__ = ["ArmV5TSysVHtons", "ArmV5TSysVNtohs", "ArmV5TSysVHtonl", "ArmV5TSysVNtohl"]
