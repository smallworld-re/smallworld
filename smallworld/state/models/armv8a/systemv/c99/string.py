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
from ..systemv import ArmV8ASysVModel


class ArmV8ASysVMemcpy(Memcpy, ArmV8ASysVModel):
    pass


class ArmV8ASysVMemmove(Memmove, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrcpy(Strcpy, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrncpy(Strncpy, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrcat(Strcat, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrncat(Strncat, ArmV8ASysVModel):
    pass


class ArmV8ASysVMemcmp(Memcmp, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrncmp(Strncmp, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrcmp(Strcmp, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrcoll(Strcoll, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrxfrm(Strxfrm, ArmV8ASysVModel):
    pass


class ArmV8ASysVMemchr(Memchr, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrchr(Strchr, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrcspn(Strcspn, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrpbrk(Strpbrk, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrrchr(Strrchr, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrspn(Strspn, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrstr(Strstr, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrtok(Strtok, ArmV8ASysVModel):
    pass


class ArmV8ASysVMemset(Memset, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrerror(Strerror, ArmV8ASysVModel):
    pass


class ArmV8ASysVStrlen(Strlen, ArmV8ASysVModel):
    pass


__all__ = [
    "ArmV8ASysVMemcpy",
    "ArmV8ASysVMemmove",
    "ArmV8ASysVStrcpy",
    "ArmV8ASysVStrncpy",
    "ArmV8ASysVStrcat",
    "ArmV8ASysVStrncat",
    "ArmV8ASysVMemcmp",
    "ArmV8ASysVStrncmp",
    "ArmV8ASysVStrcmp",
    "ArmV8ASysVStrcoll",
    "ArmV8ASysVStrxfrm",
    "ArmV8ASysVMemchr",
    "ArmV8ASysVStrchr",
    "ArmV8ASysVStrcspn",
    "ArmV8ASysVStrpbrk",
    "ArmV8ASysVStrrchr",
    "ArmV8ASysVStrspn",
    "ArmV8ASysVStrstr",
    "ArmV8ASysVStrtok",
    "ArmV8ASysVMemset",
    "ArmV8ASysVStrerror",
    "ArmV8ASysVStrlen",
]
