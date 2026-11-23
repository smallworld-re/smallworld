from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import AArch64V85ASysVModel


class AArch64V85ASysVHtons(Htons, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVNtohs(Ntohs, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVHtonl(Htonl, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVNtohl(Ntohl, AArch64V85ASysVModel):
    pass


__all__ = [
    "AArch64V85ASysVHtons",
    "AArch64V85ASysVNtohs",
    "AArch64V85ASysVHtonl",
    "AArch64V85ASysVNtohl",
]
