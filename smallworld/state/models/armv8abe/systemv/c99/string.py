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
from ..systemv import ArmV8ABESysVModel


class ArmV8ABESysVMemcpy(Memcpy, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVMemmove(Memmove, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrcpy(Strcpy, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrncpy(Strncpy, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrcat(Strcat, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrncat(Strncat, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVMemcmp(Memcmp, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrncmp(Strncmp, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrcmp(Strcmp, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrcoll(Strcoll, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrxfrm(Strxfrm, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVMemchr(Memchr, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrchr(Strchr, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrcspn(Strcspn, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrpbrk(Strpbrk, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrrchr(Strrchr, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrspn(Strspn, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrstr(Strstr, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrtok(Strtok, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVMemset(Memset, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrerror(Strerror, ArmV8ABESysVModel):
    pass


class ArmV8ABESysVStrlen(Strlen, ArmV8ABESysVModel):
    pass


__all__ = [
    "ArmV8ABESysVMemcpy",
    "ArmV8ABESysVMemmove",
    "ArmV8ABESysVStrcpy",
    "ArmV8ABESysVStrncpy",
    "ArmV8ABESysVStrcat",
    "ArmV8ABESysVStrncat",
    "ArmV8ABESysVMemcmp",
    "ArmV8ABESysVStrncmp",
    "ArmV8ABESysVStrcmp",
    "ArmV8ABESysVStrcoll",
    "ArmV8ABESysVStrxfrm",
    "ArmV8ABESysVMemchr",
    "ArmV8ABESysVStrchr",
    "ArmV8ABESysVStrcspn",
    "ArmV8ABESysVStrpbrk",
    "ArmV8ABESysVStrrchr",
    "ArmV8ABESysVStrspn",
    "ArmV8ABESysVStrstr",
    "ArmV8ABESysVStrtok",
    "ArmV8ABESysVMemset",
    "ArmV8ABESysVStrerror",
    "ArmV8ABESysVStrlen",
]
