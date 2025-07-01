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
from ..systemv import AArch64SysVModel


class AArch64SysVMemcpy(Memcpy, AArch64SysVModel):
    pass


class AArch64SysVMemmove(Memmove, AArch64SysVModel):
    pass


class AArch64SysVStrcat(Strcat, AArch64SysVModel):
    pass


class AArch64SysVStrncat(Strncat, AArch64SysVModel):
    pass


class AArch64SysVMemcmp(Memcmp, AArch64SysVModel):
    pass


class AArch64SysVStrncmp(Strncmp, AArch64SysVModel):
    pass


class AArch64SysVStrcmp(Strcmp, AArch64SysVModel):
    pass


class AArch64SysVStrcoll(Strcoll, AArch64SysVModel):
    pass


class AArch64SysVStrxfrm(Strxfrm, AArch64SysVModel):
    pass


class AArch64SysVMemchr(Memchr, AArch64SysVModel):
    pass


class AArch64SysVStrchr(Strchr, AArch64SysVModel):
    pass


class AArch64SysVStrcspn(Strcspn, AArch64SysVModel):
    pass


class AArch64SysVStrpbrk(Strpbrk, AArch64SysVModel):
    pass


class AArch64SysVStrrchr(Strrchr, AArch64SysVModel):
    pass


class AArch64SysVStrspn(Strspn, AArch64SysVModel):
    pass


class AArch64SysVStrstr(Strstr, AArch64SysVModel):
    pass


class AArch64SysVStrtok(Strtok, AArch64SysVModel):
    pass


class AArch64SysVMemset(Memset, AArch64SysVModel):
    pass


class AArch64SysVStrerror(Strerror, AArch64SysVModel):
    pass


class AArch64SysVStrlen(Strlen, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVMemcpy",
    "AArch64SysVMemmove",
    "AArch64SysVStrcat",
    "AArch64SysVStrncat",
    "AArch64SysVMemcmp",
    "AArch64SysVStrncmp",
    "AArch64SysVStrcmp",
    "AArch64SysVStrcoll",
    "AArch64SysVStrxfrm",
    "AArch64SysVMemchr",
    "AArch64SysVStrchr",
    "AArch64SysVStrcspn",
    "AArch64SysVStrpbrk",
    "AArch64SysVStrrchr",
    "AArch64SysVStrspn",
    "AArch64SysVStrstr",
    "AArch64SysVStrtok",
    "AArch64SysVMemset",
    "AArch64SysVStrerror",
    "AArch64SysVStrlen",
]
