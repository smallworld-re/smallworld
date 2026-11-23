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
from ..systemv import AArch64V85ASysVModel


class AArch64V85ASysVMemcpy(Memcpy, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVMemmove(Memmove, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrcpy(Strcpy, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrncpy(Strncpy, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrcat(Strcat, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrncat(Strncat, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVMemcmp(Memcmp, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrncmp(Strncmp, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrcmp(Strcmp, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrcoll(Strcoll, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrxfrm(Strxfrm, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVMemchr(Memchr, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrchr(Strchr, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrcspn(Strcspn, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrpbrk(Strpbrk, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrrchr(Strrchr, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrspn(Strspn, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrstr(Strstr, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrtok(Strtok, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVMemset(Memset, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrerror(Strerror, AArch64V85ASysVModel):
    pass


class AArch64V85ASysVStrlen(Strlen, AArch64V85ASysVModel):
    pass


__all__ = [
    "AArch64V85ASysVMemcpy",
    "AArch64V85ASysVMemmove",
    "AArch64V85ASysVStrcpy",
    "AArch64V85ASysVStrncpy",
    "AArch64V85ASysVStrcat",
    "AArch64V85ASysVStrncat",
    "AArch64V85ASysVMemcmp",
    "AArch64V85ASysVStrncmp",
    "AArch64V85ASysVStrcmp",
    "AArch64V85ASysVStrcoll",
    "AArch64V85ASysVStrxfrm",
    "AArch64V85ASysVMemchr",
    "AArch64V85ASysVStrchr",
    "AArch64V85ASysVStrcspn",
    "AArch64V85ASysVStrpbrk",
    "AArch64V85ASysVStrrchr",
    "AArch64V85ASysVStrspn",
    "AArch64V85ASysVStrstr",
    "AArch64V85ASysVStrtok",
    "AArch64V85ASysVMemset",
    "AArch64V85ASysVStrerror",
    "AArch64V85ASysVStrlen",
]
