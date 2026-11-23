from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV8ASysVModel


class ArmV8ASysVHtons(Htons, ArmV8ASysVModel):
    pass


class ArmV8ASysVNtohs(Ntohs, ArmV8ASysVModel):
    pass


class ArmV8ASysVHtonl(Htonl, ArmV8ASysVModel):
    pass


class ArmV8ASysVNtohl(Ntohl, ArmV8ASysVModel):
    pass


__all__ = ["ArmV8ASysVHtons", "ArmV8ASysVNtohs", "ArmV8ASysVHtonl", "ArmV8ASysVNtohl"]
