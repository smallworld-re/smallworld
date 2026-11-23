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
from ..systemv import ArmV4TBESysVModel


class ArmV4TBESysVMemcpy(Memcpy, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVMemmove(Memmove, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrcpy(Strcpy, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrncpy(Strncpy, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrcat(Strcat, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrncat(Strncat, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVMemcmp(Memcmp, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrncmp(Strncmp, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrcmp(Strcmp, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrcoll(Strcoll, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrxfrm(Strxfrm, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVMemchr(Memchr, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrchr(Strchr, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrcspn(Strcspn, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrpbrk(Strpbrk, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrrchr(Strrchr, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrspn(Strspn, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrstr(Strstr, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrtok(Strtok, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVMemset(Memset, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrerror(Strerror, ArmV4TBESysVModel):
    pass


class ArmV4TBESysVStrlen(Strlen, ArmV4TBESysVModel):
    pass


__all__ = [
    "ArmV4TBESysVMemcpy",
    "ArmV4TBESysVMemmove",
    "ArmV4TBESysVStrcpy",
    "ArmV4TBESysVStrncpy",
    "ArmV4TBESysVStrcat",
    "ArmV4TBESysVStrncat",
    "ArmV4TBESysVMemcmp",
    "ArmV4TBESysVStrncmp",
    "ArmV4TBESysVStrcmp",
    "ArmV4TBESysVStrcoll",
    "ArmV4TBESysVStrxfrm",
    "ArmV4TBESysVMemchr",
    "ArmV4TBESysVStrchr",
    "ArmV4TBESysVStrcspn",
    "ArmV4TBESysVStrpbrk",
    "ArmV4TBESysVStrrchr",
    "ArmV4TBESysVStrspn",
    "ArmV4TBESysVStrstr",
    "ArmV4TBESysVStrtok",
    "ArmV4TBESysVMemset",
    "ArmV4TBESysVStrerror",
    "ArmV4TBESysVStrlen",
]
