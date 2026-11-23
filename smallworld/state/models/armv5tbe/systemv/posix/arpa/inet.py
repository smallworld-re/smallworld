from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV5TBESysVModel


class ArmV5TBESysVHtons(Htons, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVNtohs(Ntohs, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVHtonl(Htonl, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVNtohl(Ntohl, ArmV5TBESysVModel):
    pass


__all__ = [
    "ArmV5TBESysVHtons",
    "ArmV5TBESysVNtohs",
    "ArmV5TBESysVHtonl",
    "ArmV5TBESysVNtohl",
]
