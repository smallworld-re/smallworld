from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV7ABESysVModel


class ArmV7ABESysVHtons(Htons, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVNtohs(Ntohs, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVHtonl(Htonl, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVNtohl(Ntohl, ArmV7ABESysVModel):
    pass


__all__ = [
    "ArmV7ABESysVHtons",
    "ArmV7ABESysVNtohs",
    "ArmV7ABESysVHtonl",
    "ArmV7ABESysVNtohl",
]
