from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVHtons(Htons, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVNtohs(Ntohs, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVHtonl(Htonl, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVNtohl(Ntohl, AArch64V85ABESysVModel):
    pass


__all__ = [
    "AArch64V85ABESysVHtons",
    "AArch64V85ABESysVNtohs",
    "AArch64V85ABESysVHtonl",
    "AArch64V85ABESysVNtohl",
]
