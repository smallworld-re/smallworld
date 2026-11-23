from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV8RBESysVModel


class ArmV8RBESysVHtons(Htons, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVNtohs(Ntohs, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVHtonl(Htonl, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVNtohl(Ntohl, ArmV8RBESysVModel):
    pass


__all__ = [
    "ArmV8RBESysVHtons",
    "ArmV8RBESysVNtohs",
    "ArmV8RBESysVHtonl",
    "ArmV8RBESysVNtohl",
]
