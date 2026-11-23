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
from ..systemv import AArch64BESysVModel


class AArch64BESysVMemcpy(Memcpy, AArch64BESysVModel):
    pass


class AArch64BESysVMemmove(Memmove, AArch64BESysVModel):
    pass


class AArch64BESysVStrcpy(Strcpy, AArch64BESysVModel):
    pass


class AArch64BESysVStrncpy(Strncpy, AArch64BESysVModel):
    pass


class AArch64BESysVStrcat(Strcat, AArch64BESysVModel):
    pass


class AArch64BESysVStrncat(Strncat, AArch64BESysVModel):
    pass


class AArch64BESysVMemcmp(Memcmp, AArch64BESysVModel):
    pass


class AArch64BESysVStrncmp(Strncmp, AArch64BESysVModel):
    pass


class AArch64BESysVStrcmp(Strcmp, AArch64BESysVModel):
    pass


class AArch64BESysVStrcoll(Strcoll, AArch64BESysVModel):
    pass


class AArch64BESysVStrxfrm(Strxfrm, AArch64BESysVModel):
    pass


class AArch64BESysVMemchr(Memchr, AArch64BESysVModel):
    pass


class AArch64BESysVStrchr(Strchr, AArch64BESysVModel):
    pass


class AArch64BESysVStrcspn(Strcspn, AArch64BESysVModel):
    pass


class AArch64BESysVStrpbrk(Strpbrk, AArch64BESysVModel):
    pass


class AArch64BESysVStrrchr(Strrchr, AArch64BESysVModel):
    pass


class AArch64BESysVStrspn(Strspn, AArch64BESysVModel):
    pass


class AArch64BESysVStrstr(Strstr, AArch64BESysVModel):
    pass


class AArch64BESysVStrtok(Strtok, AArch64BESysVModel):
    pass


class AArch64BESysVMemset(Memset, AArch64BESysVModel):
    pass


class AArch64BESysVStrerror(Strerror, AArch64BESysVModel):
    pass


class AArch64BESysVStrlen(Strlen, AArch64BESysVModel):
    pass


__all__ = [
    "AArch64BESysVMemcpy",
    "AArch64BESysVMemmove",
    "AArch64BESysVStrcpy",
    "AArch64BESysVStrncpy",
    "AArch64BESysVStrcat",
    "AArch64BESysVStrncat",
    "AArch64BESysVMemcmp",
    "AArch64BESysVStrncmp",
    "AArch64BESysVStrcmp",
    "AArch64BESysVStrcoll",
    "AArch64BESysVStrxfrm",
    "AArch64BESysVMemchr",
    "AArch64BESysVStrchr",
    "AArch64BESysVStrcspn",
    "AArch64BESysVStrpbrk",
    "AArch64BESysVStrrchr",
    "AArch64BESysVStrspn",
    "AArch64BESysVStrstr",
    "AArch64BESysVStrtok",
    "AArch64BESysVMemset",
    "AArch64BESysVStrerror",
    "AArch64BESysVStrlen",
]
