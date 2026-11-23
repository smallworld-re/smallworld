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
from ..systemv import ArmV8RSysVModel


class ArmV8RSysVMemcpy(Memcpy, ArmV8RSysVModel):
    pass


class ArmV8RSysVMemmove(Memmove, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrcpy(Strcpy, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrncpy(Strncpy, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrcat(Strcat, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrncat(Strncat, ArmV8RSysVModel):
    pass


class ArmV8RSysVMemcmp(Memcmp, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrncmp(Strncmp, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrcmp(Strcmp, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrcoll(Strcoll, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrxfrm(Strxfrm, ArmV8RSysVModel):
    pass


class ArmV8RSysVMemchr(Memchr, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrchr(Strchr, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrcspn(Strcspn, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrpbrk(Strpbrk, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrrchr(Strrchr, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrspn(Strspn, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrstr(Strstr, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrtok(Strtok, ArmV8RSysVModel):
    pass


class ArmV8RSysVMemset(Memset, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrerror(Strerror, ArmV8RSysVModel):
    pass


class ArmV8RSysVStrlen(Strlen, ArmV8RSysVModel):
    pass


__all__ = [
    "ArmV8RSysVMemcpy",
    "ArmV8RSysVMemmove",
    "ArmV8RSysVStrcpy",
    "ArmV8RSysVStrncpy",
    "ArmV8RSysVStrcat",
    "ArmV8RSysVStrncat",
    "ArmV8RSysVMemcmp",
    "ArmV8RSysVStrncmp",
    "ArmV8RSysVStrcmp",
    "ArmV8RSysVStrcoll",
    "ArmV8RSysVStrxfrm",
    "ArmV8RSysVMemchr",
    "ArmV8RSysVStrchr",
    "ArmV8RSysVStrcspn",
    "ArmV8RSysVStrpbrk",
    "ArmV8RSysVStrrchr",
    "ArmV8RSysVStrspn",
    "ArmV8RSysVStrstr",
    "ArmV8RSysVStrtok",
    "ArmV8RSysVMemset",
    "ArmV8RSysVStrerror",
    "ArmV8RSysVStrlen",
]
