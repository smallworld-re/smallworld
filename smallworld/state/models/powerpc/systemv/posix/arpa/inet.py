from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import PowerPCSysVModel


class PowerPCSysVHtons(Htons, PowerPCSysVModel):
    pass


class PowerPCSysVNtohs(Ntohs, PowerPCSysVModel):
    pass


class PowerPCSysVHtonl(Htonl, PowerPCSysVModel):
    pass


class PowerPCSysVNtohl(Ntohl, PowerPCSysVModel):
    pass


__all__ = [
    "PowerPCSysVHtons",
    "PowerPCSysVNtohs",
    "PowerPCSysVHtonl",
    "PowerPCSysVNtohl",
]
