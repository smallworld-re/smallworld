from ...c99 import (
    Memchr,
    Memcmp,
    Memcpy,
    Memmove,
    Memset,
    Strcat,
    Strchr,
    Strcmp,
    Strcoll,
    Strcspn,
    Strerror,
    Strlen,
    Strncat,
    Strncmp,
    Strpbrk,
    Strrchr,
    Strspn,
    Strstr,
    Strtok,
    Strxfrm,
)
from ..systemv import MIPSSysVModel


class MIPSSysVMemcpy(Memcpy, MIPSSysVModel):
    pass


class MIPSSysVMemmove(Memmove, MIPSSysVModel):
    pass


class MIPSSysVStrcat(Strcat, MIPSSysVModel):
    pass


class MIPSSysVStrncat(Strncat, MIPSSysVModel):
    pass


class MIPSSysVMemcmp(Memcmp, MIPSSysVModel):
    pass


class MIPSSysVStrncmp(Strncmp, MIPSSysVModel):
    pass


class MIPSSysVStrcmp(Strcmp, MIPSSysVModel):
    pass


class MIPSSysVStrcoll(Strcoll, MIPSSysVModel):
    pass


class MIPSSysVStrxfrm(Strxfrm, MIPSSysVModel):
    pass


class MIPSSysVMemchr(Memchr, MIPSSysVModel):
    pass


class MIPSSysVStrchr(Strchr, MIPSSysVModel):
    pass


class MIPSSysVStrcspn(Strcspn, MIPSSysVModel):
    pass


class MIPSSysVStrpbrk(Strpbrk, MIPSSysVModel):
    pass


class MIPSSysVStrrchr(Strrchr, MIPSSysVModel):
    pass


class MIPSSysVStrspn(Strspn, MIPSSysVModel):
    pass


class MIPSSysVStrstr(Strstr, MIPSSysVModel):
    pass


class MIPSSysVStrtok(Strtok, MIPSSysVModel):
    pass


class MIPSSysVMemset(Memset, MIPSSysVModel):
    pass


class MIPSSysVStrerror(Strerror, MIPSSysVModel):
    pass


class MIPSSysVStrlen(Strlen, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVMemcpy",
    "MIPSSysVMemmove",
    "MIPSSysVStrcat",
    "MIPSSysVStrncat",
    "MIPSSysVMemcmp",
    "MIPSSysVStrncmp",
    "MIPSSysVStrcmp",
    "MIPSSysVStrcoll",
    "MIPSSysVStrxfrm",
    "MIPSSysVMemchr",
    "MIPSSysVStrchr",
    "MIPSSysVStrcspn",
    "MIPSSysVStrpbrk",
    "MIPSSysVStrrchr",
    "MIPSSysVStrspn",
    "MIPSSysVStrstr",
    "MIPSSysVStrtok",
    "MIPSSysVMemset",
    "MIPSSysVStrerror",
    "MIPSSysVStrlen",
]
