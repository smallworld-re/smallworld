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
from ..systemv import ArmV5TBESysVModel


class ArmV5TBESysVMemcpy(Memcpy, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVMemmove(Memmove, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrcpy(Strcpy, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrncpy(Strncpy, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrcat(Strcat, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrncat(Strncat, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVMemcmp(Memcmp, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrncmp(Strncmp, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrcmp(Strcmp, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrcoll(Strcoll, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrxfrm(Strxfrm, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVMemchr(Memchr, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrchr(Strchr, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrcspn(Strcspn, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrpbrk(Strpbrk, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrrchr(Strrchr, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrspn(Strspn, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrstr(Strstr, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrtok(Strtok, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVMemset(Memset, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrerror(Strerror, ArmV5TBESysVModel):
    pass


class ArmV5TBESysVStrlen(Strlen, ArmV5TBESysVModel):
    pass


__all__ = [
    "ArmV5TBESysVMemcpy",
    "ArmV5TBESysVMemmove",
    "ArmV5TBESysVStrcpy",
    "ArmV5TBESysVStrncpy",
    "ArmV5TBESysVStrcat",
    "ArmV5TBESysVStrncat",
    "ArmV5TBESysVMemcmp",
    "ArmV5TBESysVStrncmp",
    "ArmV5TBESysVStrcmp",
    "ArmV5TBESysVStrcoll",
    "ArmV5TBESysVStrxfrm",
    "ArmV5TBESysVMemchr",
    "ArmV5TBESysVStrchr",
    "ArmV5TBESysVStrcspn",
    "ArmV5TBESysVStrpbrk",
    "ArmV5TBESysVStrrchr",
    "ArmV5TBESysVStrspn",
    "ArmV5TBESysVStrstr",
    "ArmV5TBESysVStrtok",
    "ArmV5TBESysVMemset",
    "ArmV5TBESysVStrerror",
    "ArmV5TBESysVStrlen",
]
