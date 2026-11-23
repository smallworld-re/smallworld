from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV6MSysVModel


class ArmV6MSysVHtons(Htons, ArmV6MSysVModel):
    pass


class ArmV6MSysVNtohs(Ntohs, ArmV6MSysVModel):
    pass


class ArmV6MSysVHtonl(Htonl, ArmV6MSysVModel):
    pass


class ArmV6MSysVNtohl(Ntohl, ArmV6MSysVModel):
    pass


__all__ = ["ArmV6MSysVHtons", "ArmV6MSysVNtohs", "ArmV6MSysVHtonl", "ArmV6MSysVNtohl"]
