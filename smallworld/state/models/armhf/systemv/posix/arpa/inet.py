from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import ArmHFSysVModel


class ArmHFSysVHtons(Htons, ArmHFSysVModel):
    pass


class ArmHFSysVNtohs(Ntohs, ArmHFSysVModel):
    pass


class ArmHFSysVHtonl(Htonl, ArmHFSysVModel):
    pass


class ArmHFSysVNtohl(Ntohl, ArmHFSysVModel):
    pass


__all__ = ["ArmHFSysVHtons", "ArmHFSysVNtohs", "ArmHFSysVHtonl", "ArmHFSysVNtohl"]
