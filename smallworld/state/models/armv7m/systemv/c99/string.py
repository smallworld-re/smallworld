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
from ..systemv import ArmV7MSysVModel


class ArmV7MSysVMemcpy(Memcpy, ArmV7MSysVModel):
    pass


class ArmV7MSysVMemmove(Memmove, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrcpy(Strcpy, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrncpy(Strncpy, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrcat(Strcat, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrncat(Strncat, ArmV7MSysVModel):
    pass


class ArmV7MSysVMemcmp(Memcmp, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrncmp(Strncmp, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrcmp(Strcmp, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrcoll(Strcoll, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrxfrm(Strxfrm, ArmV7MSysVModel):
    pass


class ArmV7MSysVMemchr(Memchr, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrchr(Strchr, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrcspn(Strcspn, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrpbrk(Strpbrk, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrrchr(Strrchr, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrspn(Strspn, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrstr(Strstr, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrtok(Strtok, ArmV7MSysVModel):
    pass


class ArmV7MSysVMemset(Memset, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrerror(Strerror, ArmV7MSysVModel):
    pass


class ArmV7MSysVStrlen(Strlen, ArmV7MSysVModel):
    pass


__all__ = [
    "ArmV7MSysVMemcpy",
    "ArmV7MSysVMemmove",
    "ArmV7MSysVStrcpy",
    "ArmV7MSysVStrncpy",
    "ArmV7MSysVStrcat",
    "ArmV7MSysVStrncat",
    "ArmV7MSysVMemcmp",
    "ArmV7MSysVStrncmp",
    "ArmV7MSysVStrcmp",
    "ArmV7MSysVStrcoll",
    "ArmV7MSysVStrxfrm",
    "ArmV7MSysVMemchr",
    "ArmV7MSysVStrchr",
    "ArmV7MSysVStrcspn",
    "ArmV7MSysVStrpbrk",
    "ArmV7MSysVStrrchr",
    "ArmV7MSysVStrspn",
    "ArmV7MSysVStrstr",
    "ArmV7MSysVStrtok",
    "ArmV7MSysVMemset",
    "ArmV7MSysVStrerror",
    "ArmV7MSysVStrlen",
]
