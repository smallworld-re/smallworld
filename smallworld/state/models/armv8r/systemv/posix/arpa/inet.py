from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV8RSysVModel


class ArmV8RSysVHtons(Htons, ArmV8RSysVModel):
    pass


class ArmV8RSysVNtohs(Ntohs, ArmV8RSysVModel):
    pass


class ArmV8RSysVHtonl(Htonl, ArmV8RSysVModel):
    pass


class ArmV8RSysVNtohl(Ntohl, ArmV8RSysVModel):
    pass


__all__ = ["ArmV8RSysVHtons", "ArmV8RSysVNtohs", "ArmV8RSysVHtonl", "ArmV8RSysVNtohl"]
