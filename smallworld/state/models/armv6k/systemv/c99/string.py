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
from ..systemv import ArmV6KSysVModel


class ArmV6KSysVMemcpy(Memcpy, ArmV6KSysVModel):
    pass


class ArmV6KSysVMemmove(Memmove, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrcpy(Strcpy, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrncpy(Strncpy, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrcat(Strcat, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrncat(Strncat, ArmV6KSysVModel):
    pass


class ArmV6KSysVMemcmp(Memcmp, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrncmp(Strncmp, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrcmp(Strcmp, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrcoll(Strcoll, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrxfrm(Strxfrm, ArmV6KSysVModel):
    pass


class ArmV6KSysVMemchr(Memchr, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrchr(Strchr, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrcspn(Strcspn, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrpbrk(Strpbrk, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrrchr(Strrchr, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrspn(Strspn, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrstr(Strstr, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrtok(Strtok, ArmV6KSysVModel):
    pass


class ArmV6KSysVMemset(Memset, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrerror(Strerror, ArmV6KSysVModel):
    pass


class ArmV6KSysVStrlen(Strlen, ArmV6KSysVModel):
    pass


__all__ = [
    "ArmV6KSysVMemcpy",
    "ArmV6KSysVMemmove",
    "ArmV6KSysVStrcpy",
    "ArmV6KSysVStrncpy",
    "ArmV6KSysVStrcat",
    "ArmV6KSysVStrncat",
    "ArmV6KSysVMemcmp",
    "ArmV6KSysVStrncmp",
    "ArmV6KSysVStrcmp",
    "ArmV6KSysVStrcoll",
    "ArmV6KSysVStrxfrm",
    "ArmV6KSysVMemchr",
    "ArmV6KSysVStrchr",
    "ArmV6KSysVStrcspn",
    "ArmV6KSysVStrpbrk",
    "ArmV6KSysVStrrchr",
    "ArmV6KSysVStrspn",
    "ArmV6KSysVStrstr",
    "ArmV6KSysVStrtok",
    "ArmV6KSysVMemset",
    "ArmV6KSysVStrerror",
    "ArmV6KSysVStrlen",
]
