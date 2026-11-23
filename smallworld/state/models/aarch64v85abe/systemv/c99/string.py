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
from ..systemv import AArch64V85ABESysVModel


class AArch64V85ABESysVMemcpy(Memcpy, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVMemmove(Memmove, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrcpy(Strcpy, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrncpy(Strncpy, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrcat(Strcat, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrncat(Strncat, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVMemcmp(Memcmp, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrncmp(Strncmp, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrcmp(Strcmp, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrcoll(Strcoll, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrxfrm(Strxfrm, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVMemchr(Memchr, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrchr(Strchr, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrcspn(Strcspn, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrpbrk(Strpbrk, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrrchr(Strrchr, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrspn(Strspn, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrstr(Strstr, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrtok(Strtok, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVMemset(Memset, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrerror(Strerror, AArch64V85ABESysVModel):
    pass


class AArch64V85ABESysVStrlen(Strlen, AArch64V85ABESysVModel):
    pass


__all__ = [
    "AArch64V85ABESysVMemcpy",
    "AArch64V85ABESysVMemmove",
    "AArch64V85ABESysVStrcpy",
    "AArch64V85ABESysVStrncpy",
    "AArch64V85ABESysVStrcat",
    "AArch64V85ABESysVStrncat",
    "AArch64V85ABESysVMemcmp",
    "AArch64V85ABESysVStrncmp",
    "AArch64V85ABESysVStrcmp",
    "AArch64V85ABESysVStrcoll",
    "AArch64V85ABESysVStrxfrm",
    "AArch64V85ABESysVMemchr",
    "AArch64V85ABESysVStrchr",
    "AArch64V85ABESysVStrcspn",
    "AArch64V85ABESysVStrpbrk",
    "AArch64V85ABESysVStrrchr",
    "AArch64V85ABESysVStrspn",
    "AArch64V85ABESysVStrstr",
    "AArch64V85ABESysVStrtok",
    "AArch64V85ABESysVMemset",
    "AArch64V85ABESysVStrerror",
    "AArch64V85ABESysVStrlen",
]
