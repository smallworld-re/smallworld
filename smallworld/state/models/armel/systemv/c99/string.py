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
from ..systemv import ArmELSysVModel


class ArmELSysVMemcpy(Memcpy, ArmELSysVModel):
    pass


class ArmELSysVMemmove(Memmove, ArmELSysVModel):
    pass


class ArmELSysVStrcat(Strcat, ArmELSysVModel):
    pass


class ArmELSysVStrncat(Strncat, ArmELSysVModel):
    pass


class ArmELSysVMemcmp(Memcmp, ArmELSysVModel):
    pass


class ArmELSysVStrncmp(Strncmp, ArmELSysVModel):
    pass


class ArmELSysVStrcmp(Strcmp, ArmELSysVModel):
    pass


class ArmELSysVStrcoll(Strcoll, ArmELSysVModel):
    pass


class ArmELSysVStrxfrm(Strxfrm, ArmELSysVModel):
    pass


class ArmELSysVMemchr(Memchr, ArmELSysVModel):
    pass


class ArmELSysVStrchr(Strchr, ArmELSysVModel):
    pass


class ArmELSysVStrcspn(Strcspn, ArmELSysVModel):
    pass


class ArmELSysVStrpbrk(Strpbrk, ArmELSysVModel):
    pass


class ArmELSysVStrrchr(Strrchr, ArmELSysVModel):
    pass


class ArmELSysVStrspn(Strspn, ArmELSysVModel):
    pass


class ArmELSysVStrstr(Strstr, ArmELSysVModel):
    pass


class ArmELSysVStrtok(Strtok, ArmELSysVModel):
    pass


class ArmELSysVMemset(Memset, ArmELSysVModel):
    pass


class ArmELSysVStrerror(Strerror, ArmELSysVModel):
    pass


class ArmELSysVStrlen(Strlen, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVMemcpy",
    "ArmELSysVMemmove",
    "ArmELSysVStrcat",
    "ArmELSysVStrncat",
    "ArmELSysVMemcmp",
    "ArmELSysVStrncmp",
    "ArmELSysVStrcmp",
    "ArmELSysVStrcoll",
    "ArmELSysVStrxfrm",
    "ArmELSysVMemchr",
    "ArmELSysVStrchr",
    "ArmELSysVStrcspn",
    "ArmELSysVStrpbrk",
    "ArmELSysVStrrchr",
    "ArmELSysVStrspn",
    "ArmELSysVStrstr",
    "ArmELSysVStrtok",
    "ArmELSysVMemset",
    "ArmELSysVStrerror",
    "ArmELSysVStrlen",
]
