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
from ..systemv import ArmV7EMSysVModel


class ArmV7EMSysVMemcpy(Memcpy, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMemmove(Memmove, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrcpy(Strcpy, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrncpy(Strncpy, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrcat(Strcat, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrncat(Strncat, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMemcmp(Memcmp, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrncmp(Strncmp, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrcmp(Strcmp, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrcoll(Strcoll, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrxfrm(Strxfrm, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMemchr(Memchr, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrchr(Strchr, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrcspn(Strcspn, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrpbrk(Strpbrk, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrrchr(Strrchr, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrspn(Strspn, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrstr(Strstr, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrtok(Strtok, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVMemset(Memset, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrerror(Strerror, ArmV7EMSysVModel):
    pass


class ArmV7EMSysVStrlen(Strlen, ArmV7EMSysVModel):
    pass


__all__ = [
    "ArmV7EMSysVMemcpy",
    "ArmV7EMSysVMemmove",
    "ArmV7EMSysVStrcpy",
    "ArmV7EMSysVStrncpy",
    "ArmV7EMSysVStrcat",
    "ArmV7EMSysVStrncat",
    "ArmV7EMSysVMemcmp",
    "ArmV7EMSysVStrncmp",
    "ArmV7EMSysVStrcmp",
    "ArmV7EMSysVStrcoll",
    "ArmV7EMSysVStrxfrm",
    "ArmV7EMSysVMemchr",
    "ArmV7EMSysVStrchr",
    "ArmV7EMSysVStrcspn",
    "ArmV7EMSysVStrpbrk",
    "ArmV7EMSysVStrrchr",
    "ArmV7EMSysVStrspn",
    "ArmV7EMSysVStrstr",
    "ArmV7EMSysVStrtok",
    "ArmV7EMSysVMemset",
    "ArmV7EMSysVStrerror",
    "ArmV7EMSysVStrlen",
]
