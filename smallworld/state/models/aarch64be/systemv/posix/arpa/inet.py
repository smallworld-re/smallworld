from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import AArch64BESysVModel


class AArch64BESysVHtons(Htons, AArch64BESysVModel):
    pass


class AArch64BESysVNtohs(Ntohs, AArch64BESysVModel):
    pass


class AArch64BESysVHtonl(Htonl, AArch64BESysVModel):
    pass


class AArch64BESysVNtohl(Ntohl, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVHtons",
    "AArch64BESysVNtohs",
    "AArch64BESysVHtonl",
    "AArch64BESysVNtohl",
]
