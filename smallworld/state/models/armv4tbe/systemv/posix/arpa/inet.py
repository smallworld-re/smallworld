from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV4TBESysVModel


class ArmV4TBESysVHtons(Htons, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVNtohs(Ntohs, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVHtonl(Htonl, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVNtohl(Ntohl, ArmV4TBESysVModel):
    pass


__all__ = [
    "ArmV4TBESysVHtons",
    "ArmV4TBESysVNtohs",
    "ArmV4TBESysVHtonl",
    "ArmV4TBESysVNtohl",
]
