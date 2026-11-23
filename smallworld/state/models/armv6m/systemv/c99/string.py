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
from ..systemv import ArmV6MSysVModel


class ArmV6MSysVMemcpy(Memcpy, ArmV6MSysVModel):
    pass


class ArmV6MSysVMemmove(Memmove, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrcpy(Strcpy, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrncpy(Strncpy, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrcat(Strcat, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrncat(Strncat, ArmV6MSysVModel):
    pass


class ArmV6MSysVMemcmp(Memcmp, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrncmp(Strncmp, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrcmp(Strcmp, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrcoll(Strcoll, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrxfrm(Strxfrm, ArmV6MSysVModel):
    pass


class ArmV6MSysVMemchr(Memchr, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrchr(Strchr, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrcspn(Strcspn, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrpbrk(Strpbrk, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrrchr(Strrchr, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrspn(Strspn, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrstr(Strstr, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrtok(Strtok, ArmV6MSysVModel):
    pass


class ArmV6MSysVMemset(Memset, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrerror(Strerror, ArmV6MSysVModel):
    pass


class ArmV6MSysVStrlen(Strlen, ArmV6MSysVModel):
    pass


__all__ = [
    "ArmV6MSysVMemcpy",
    "ArmV6MSysVMemmove",
    "ArmV6MSysVStrcpy",
    "ArmV6MSysVStrncpy",
    "ArmV6MSysVStrcat",
    "ArmV6MSysVStrncat",
    "ArmV6MSysVMemcmp",
    "ArmV6MSysVStrncmp",
    "ArmV6MSysVStrcmp",
    "ArmV6MSysVStrcoll",
    "ArmV6MSysVStrxfrm",
    "ArmV6MSysVMemchr",
    "ArmV6MSysVStrchr",
    "ArmV6MSysVStrcspn",
    "ArmV6MSysVStrpbrk",
    "ArmV6MSysVStrrchr",
    "ArmV6MSysVStrspn",
    "ArmV6MSysVStrstr",
    "ArmV6MSysVStrtok",
    "ArmV6MSysVMemset",
    "ArmV6MSysVStrerror",
    "ArmV6MSysVStrlen",
]
