from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import MicroMIPSSysVModel


class MicroMIPSSysVHtons(Htons, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVNtohs(Ntohs, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVHtonl(Htonl, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVNtohl(Ntohl, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVHtons",
    "MicroMIPSSysVNtohs",
    "MicroMIPSSysVHtonl",
    "MicroMIPSSysVNtohl",
]
