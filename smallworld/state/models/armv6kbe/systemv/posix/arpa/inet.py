from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV6KBESysVModel


class ArmV6KBESysVHtons(Htons, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVNtohs(Ntohs, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVHtonl(Htonl, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVNtohl(Ntohl, ArmV6KBESysVModel):
    pass


__all__ = [
    "ArmV6KBESysVHtons",
    "ArmV6KBESysVNtohs",
    "ArmV6KBESysVHtonl",
    "ArmV6KBESysVNtohl",
]
