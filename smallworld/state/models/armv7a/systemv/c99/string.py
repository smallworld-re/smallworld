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
from ..systemv import ArmV7ASysVModel


class ArmV7ASysVMemcpy(Memcpy, ArmV7ASysVModel):
    pass


class ArmV7ASysVMemmove(Memmove, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrcpy(Strcpy, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrncpy(Strncpy, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrcat(Strcat, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrncat(Strncat, ArmV7ASysVModel):
    pass


class ArmV7ASysVMemcmp(Memcmp, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrncmp(Strncmp, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrcmp(Strcmp, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrcoll(Strcoll, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrxfrm(Strxfrm, ArmV7ASysVModel):
    pass


class ArmV7ASysVMemchr(Memchr, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrchr(Strchr, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrcspn(Strcspn, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrpbrk(Strpbrk, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrrchr(Strrchr, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrspn(Strspn, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrstr(Strstr, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrtok(Strtok, ArmV7ASysVModel):
    pass


class ArmV7ASysVMemset(Memset, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrerror(Strerror, ArmV7ASysVModel):
    pass


class ArmV7ASysVStrlen(Strlen, ArmV7ASysVModel):
    pass


__all__ = [
    "ArmV7ASysVMemcpy",
    "ArmV7ASysVMemmove",
    "ArmV7ASysVStrcpy",
    "ArmV7ASysVStrncpy",
    "ArmV7ASysVStrcat",
    "ArmV7ASysVStrncat",
    "ArmV7ASysVMemcmp",
    "ArmV7ASysVStrncmp",
    "ArmV7ASysVStrcmp",
    "ArmV7ASysVStrcoll",
    "ArmV7ASysVStrxfrm",
    "ArmV7ASysVMemchr",
    "ArmV7ASysVStrchr",
    "ArmV7ASysVStrcspn",
    "ArmV7ASysVStrpbrk",
    "ArmV7ASysVStrrchr",
    "ArmV7ASysVStrspn",
    "ArmV7ASysVStrstr",
    "ArmV7ASysVStrtok",
    "ArmV7ASysVMemset",
    "ArmV7ASysVStrerror",
    "ArmV7ASysVStrlen",
]
