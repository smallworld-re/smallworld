from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV4TSysVModel


class ArmV4TSysVHtons(Htons, ArmV4TSysVModel):
    pass


class ArmV4TSysVNtohs(Ntohs, ArmV4TSysVModel):
    pass


class ArmV4TSysVHtonl(Htonl, ArmV4TSysVModel):
    pass


class ArmV4TSysVNtohl(Ntohl, ArmV4TSysVModel):
    pass


__all__ = ["ArmV4TSysVHtons", "ArmV4TSysVNtohs", "ArmV4TSysVHtonl", "ArmV4TSysVNtohl"]
