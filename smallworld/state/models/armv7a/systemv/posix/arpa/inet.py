from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV7ASysVModel


class ArmV7ASysVHtons(Htons, ArmV7ASysVModel):
    pass


class ArmV7ASysVNtohs(Ntohs, ArmV7ASysVModel):
    pass


class ArmV7ASysVHtonl(Htonl, ArmV7ASysVModel):
    pass


class ArmV7ASysVNtohl(Ntohl, ArmV7ASysVModel):
    pass


__all__ = ["ArmV7ASysVHtons", "ArmV7ASysVNtohs", "ArmV7ASysVHtonl", "ArmV7ASysVNtohl"]
