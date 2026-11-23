from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmV7MSysVModel


class ArmV7MSysVHtons(Htons, ArmV7MSysVModel):
    pass


class ArmV7MSysVNtohs(Ntohs, ArmV7MSysVModel):
    pass


class ArmV7MSysVHtonl(Htonl, ArmV7MSysVModel):
    pass


class ArmV7MSysVNtohl(Ntohl, ArmV7MSysVModel):
    pass


__all__ = ["ArmV7MSysVHtons", "ArmV7MSysVNtohs", "ArmV7MSysVHtonl", "ArmV7MSysVNtohl"]
