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
from ..systemv import ArmV8MSysVModel


class ArmV8MSysVMemcpy(Memcpy, ArmV8MSysVModel):
    pass


class ArmV8MSysVMemmove(Memmove, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrcpy(Strcpy, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrncpy(Strncpy, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrcat(Strcat, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrncat(Strncat, ArmV8MSysVModel):
    pass


class ArmV8MSysVMemcmp(Memcmp, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrncmp(Strncmp, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrcmp(Strcmp, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrcoll(Strcoll, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrxfrm(Strxfrm, ArmV8MSysVModel):
    pass


class ArmV8MSysVMemchr(Memchr, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrchr(Strchr, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrcspn(Strcspn, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrpbrk(Strpbrk, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrrchr(Strrchr, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrspn(Strspn, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrstr(Strstr, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrtok(Strtok, ArmV8MSysVModel):
    pass


class ArmV8MSysVMemset(Memset, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrerror(Strerror, ArmV8MSysVModel):
    pass


class ArmV8MSysVStrlen(Strlen, ArmV8MSysVModel):
    pass


__all__ = [
    "ArmV8MSysVMemcpy",
    "ArmV8MSysVMemmove",
    "ArmV8MSysVStrcpy",
    "ArmV8MSysVStrncpy",
    "ArmV8MSysVStrcat",
    "ArmV8MSysVStrncat",
    "ArmV8MSysVMemcmp",
    "ArmV8MSysVStrncmp",
    "ArmV8MSysVStrcmp",
    "ArmV8MSysVStrcoll",
    "ArmV8MSysVStrxfrm",
    "ArmV8MSysVMemchr",
    "ArmV8MSysVStrchr",
    "ArmV8MSysVStrcspn",
    "ArmV8MSysVStrpbrk",
    "ArmV8MSysVStrrchr",
    "ArmV8MSysVStrspn",
    "ArmV8MSysVStrstr",
    "ArmV8MSysVStrtok",
    "ArmV8MSysVMemset",
    "ArmV8MSysVStrerror",
    "ArmV8MSysVStrlen",
]
