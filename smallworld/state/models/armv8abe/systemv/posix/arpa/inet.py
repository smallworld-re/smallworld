from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV8ABESysVModel


class ArmV8ABESysVHtons(Htons, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVNtohs(Ntohs, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVHtonl(Htonl, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVNtohl(Ntohl, ArmV8ABESysVModel):
    pass


__all__ = [
    "ArmV8ABESysVHtons",
    "ArmV8ABESysVNtohs",
    "ArmV8ABESysVHtonl",
    "ArmV8ABESysVNtohl",
]
