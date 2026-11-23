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
from ..systemv import ArmV7RSysVModel


class ArmV7RSysVMemcpy(Memcpy, ArmV7RSysVModel):
    pass


class ArmV7RSysVMemmove(Memmove, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrcpy(Strcpy, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrncpy(Strncpy, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrcat(Strcat, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrncat(Strncat, ArmV7RSysVModel):
    pass


class ArmV7RSysVMemcmp(Memcmp, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrncmp(Strncmp, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrcmp(Strcmp, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrcoll(Strcoll, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrxfrm(Strxfrm, ArmV7RSysVModel):
    pass


class ArmV7RSysVMemchr(Memchr, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrchr(Strchr, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrcspn(Strcspn, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrpbrk(Strpbrk, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrrchr(Strrchr, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrspn(Strspn, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrstr(Strstr, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrtok(Strtok, ArmV7RSysVModel):
    pass


class ArmV7RSysVMemset(Memset, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrerror(Strerror, ArmV7RSysVModel):
    pass


class ArmV7RSysVStrlen(Strlen, ArmV7RSysVModel):
    pass


__all__ = [
    "ArmV7RSysVMemcpy",
    "ArmV7RSysVMemmove",
    "ArmV7RSysVStrcpy",
    "ArmV7RSysVStrncpy",
    "ArmV7RSysVStrcat",
    "ArmV7RSysVStrncat",
    "ArmV7RSysVMemcmp",
    "ArmV7RSysVStrncmp",
    "ArmV7RSysVStrcmp",
    "ArmV7RSysVStrcoll",
    "ArmV7RSysVStrxfrm",
    "ArmV7RSysVMemchr",
    "ArmV7RSysVStrchr",
    "ArmV7RSysVStrcspn",
    "ArmV7RSysVStrpbrk",
    "ArmV7RSysVStrrchr",
    "ArmV7RSysVStrspn",
    "ArmV7RSysVStrstr",
    "ArmV7RSysVStrtok",
    "ArmV7RSysVMemset",
    "ArmV7RSysVStrerror",
    "ArmV7RSysVStrlen",
]
