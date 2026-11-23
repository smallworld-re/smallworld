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
from ..systemv import ArmV4TSysVModel


class ArmV4TSysVMemcpy(Memcpy, ArmV4TSysVModel):
    pass


class ArmV4TSysVMemmove(Memmove, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrcpy(Strcpy, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrncpy(Strncpy, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrcat(Strcat, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrncat(Strncat, ArmV4TSysVModel):
    pass


class ArmV4TSysVMemcmp(Memcmp, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrncmp(Strncmp, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrcmp(Strcmp, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrcoll(Strcoll, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrxfrm(Strxfrm, ArmV4TSysVModel):
    pass


class ArmV4TSysVMemchr(Memchr, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrchr(Strchr, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrcspn(Strcspn, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrpbrk(Strpbrk, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrrchr(Strrchr, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrspn(Strspn, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrstr(Strstr, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrtok(Strtok, ArmV4TSysVModel):
    pass


class ArmV4TSysVMemset(Memset, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrerror(Strerror, ArmV4TSysVModel):
    pass


class ArmV4TSysVStrlen(Strlen, ArmV4TSysVModel):
    pass


__all__ = [
    "ArmV4TSysVMemcpy",
    "ArmV4TSysVMemmove",
    "ArmV4TSysVStrcpy",
    "ArmV4TSysVStrncpy",
    "ArmV4TSysVStrcat",
    "ArmV4TSysVStrncat",
    "ArmV4TSysVMemcmp",
    "ArmV4TSysVStrncmp",
    "ArmV4TSysVStrcmp",
    "ArmV4TSysVStrcoll",
    "ArmV4TSysVStrxfrm",
    "ArmV4TSysVMemchr",
    "ArmV4TSysVStrchr",
    "ArmV4TSysVStrcspn",
    "ArmV4TSysVStrpbrk",
    "ArmV4TSysVStrrchr",
    "ArmV4TSysVStrspn",
    "ArmV4TSysVStrstr",
    "ArmV4TSysVStrtok",
    "ArmV4TSysVMemset",
    "ArmV4TSysVStrerror",
    "ArmV4TSysVStrlen",
]
