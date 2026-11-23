from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV7RSysVModel


class ArmV7RSysVHtons(Htons, ArmV7RSysVModel):
    pass


class ArmV7RSysVNtohs(Ntohs, ArmV7RSysVModel):
    pass


class ArmV7RSysVHtonl(Htonl, ArmV7RSysVModel):
    pass


class ArmV7RSysVNtohl(Ntohl, ArmV7RSysVModel):
    pass


__all__ = ["ArmV7RSysVHtons", "ArmV7RSysVNtohs", "ArmV7RSysVHtonl", "ArmV7RSysVNtohl"]
