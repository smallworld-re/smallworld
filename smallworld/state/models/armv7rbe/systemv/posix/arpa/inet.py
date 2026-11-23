from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV7RBESysVModel


class ArmV7RBESysVHtons(Htons, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVNtohs(Ntohs, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVHtonl(Htonl, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVNtohl(Ntohl, ArmV7RBESysVModel):
    pass


__all__ = [
    "ArmV7RBESysVHtons",
    "ArmV7RBESysVNtohs",
    "ArmV7RBESysVHtonl",
    "ArmV7RBESysVNtohl",
]
