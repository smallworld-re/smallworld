from ....c99 import (
    Memchr,
    Memcmp,
    Memcpy,
    Memmove,
    Memset,
    Strcat,
    Strchr,
    Strcmp,
    Strcoll,
    Strcpy,
    Strcspn,
    Strerror,
    Strlen,
    Strncat,
    Strncmp,
    Strncpy,
    Strpbrk,
    Strrchr,
    Strspn,
    Strstr,
    Strtok,
    Strxfrm,
)
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVMemcpy(Memcpy, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVMemmove(Memmove, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrcpy(Strcpy, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrncpy(Strncpy, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrcat(Strcat, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrncat(Strncat, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVMemcmp(Memcmp, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrncmp(Strncmp, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrcmp(Strcmp, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrcoll(Strcoll, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrxfrm(Strxfrm, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVMemchr(Memchr, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrchr(Strchr, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrcspn(Strcspn, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrpbrk(Strpbrk, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrrchr(Strrchr, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrspn(Strspn, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrstr(Strstr, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrtok(Strtok, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVMemset(Memset, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrerror(Strerror, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVStrlen(Strlen, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVMemcpy",
    "MicroMIPSSysVMemmove",
    "MicroMIPSSysVStrcpy",
    "MicroMIPSSysVStrncpy",
    "MicroMIPSSysVStrcat",
    "MicroMIPSSysVStrncat",
    "MicroMIPSSysVMemcmp",
    "MicroMIPSSysVStrncmp",
    "MicroMIPSSysVStrcmp",
    "MicroMIPSSysVStrcoll",
    "MicroMIPSSysVStrxfrm",
    "MicroMIPSSysVMemchr",
    "MicroMIPSSysVStrchr",
    "MicroMIPSSysVStrcspn",
    "MicroMIPSSysVStrpbrk",
    "MicroMIPSSysVStrrchr",
    "MicroMIPSSysVStrspn",
    "MicroMIPSSysVStrstr",
    "MicroMIPSSysVStrtok",
    "MicroMIPSSysVMemset",
    "MicroMIPSSysVStrerror",
    "MicroMIPSSysVStrlen",
]
