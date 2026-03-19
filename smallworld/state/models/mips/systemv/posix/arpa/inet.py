from .....posix.arpa.inet import Htonl, Htons, Ntohl, Ntohs
from ...systemv import MIPSSysVModel


class MIPSSysVHtons(Htons, MIPSSysVModel):
    pass


class MIPSSysVNtohs(Ntohs, MIPSSysVModel):
    pass


class MIPSSysVHtonl(Htonl, MIPSSysVModel):
    pass


class MIPSSysVNtohl(Ntohl, MIPSSysVModel):
    pass


__all__ = ["MIPSSysVHtons", "MIPSSysVNtohs", "MIPSSysVHtonl", "MIPSSysVNtohl"]
