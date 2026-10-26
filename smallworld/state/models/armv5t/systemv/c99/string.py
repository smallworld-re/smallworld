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
from ..systemv import ArmV5TSysVModel


class ArmV5TSysVMemcpy(Memcpy, ArmV5TSysVModel):
    pass


class ArmV5TSysVMemmove(Memmove, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrcpy(Strcpy, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrncpy(Strncpy, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrcat(Strcat, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrncat(Strncat, ArmV5TSysVModel):
    pass


class ArmV5TSysVMemcmp(Memcmp, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrncmp(Strncmp, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrcmp(Strcmp, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrcoll(Strcoll, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrxfrm(Strxfrm, ArmV5TSysVModel):
    pass


class ArmV5TSysVMemchr(Memchr, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrchr(Strchr, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrcspn(Strcspn, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrpbrk(Strpbrk, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrrchr(Strrchr, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrspn(Strspn, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrstr(Strstr, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrtok(Strtok, ArmV5TSysVModel):
    pass


class ArmV5TSysVMemset(Memset, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrerror(Strerror, ArmV5TSysVModel):
    pass


class ArmV5TSysVStrlen(Strlen, ArmV5TSysVModel):
    pass


__all__ = [
    "ArmV5TSysVMemcpy",
    "ArmV5TSysVMemmove",
    "ArmV5TSysVStrcpy",
    "ArmV5TSysVStrncpy",
    "ArmV5TSysVStrcat",
    "ArmV5TSysVStrncat",
    "ArmV5TSysVMemcmp",
    "ArmV5TSysVStrncmp",
    "ArmV5TSysVStrcmp",
    "ArmV5TSysVStrcoll",
    "ArmV5TSysVStrxfrm",
    "ArmV5TSysVMemchr",
    "ArmV5TSysVStrchr",
    "ArmV5TSysVStrcspn",
    "ArmV5TSysVStrpbrk",
    "ArmV5TSysVStrrchr",
    "ArmV5TSysVStrspn",
    "ArmV5TSysVStrstr",
    "ArmV5TSysVStrtok",
    "ArmV5TSysVMemset",
    "ArmV5TSysVStrerror",
    "ArmV5TSysVStrlen",
]
