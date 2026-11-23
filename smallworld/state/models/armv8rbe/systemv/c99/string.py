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
from ..systemv import ArmV8RBESysVModel


class ArmV8RBESysVMemcpy(Memcpy, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVMemmove(Memmove, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrcpy(Strcpy, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrncpy(Strncpy, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrcat(Strcat, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrncat(Strncat, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVMemcmp(Memcmp, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrncmp(Strncmp, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrcmp(Strcmp, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrcoll(Strcoll, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrxfrm(Strxfrm, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVMemchr(Memchr, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrchr(Strchr, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrcspn(Strcspn, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrpbrk(Strpbrk, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrrchr(Strrchr, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrspn(Strspn, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrstr(Strstr, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrtok(Strtok, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVMemset(Memset, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrerror(Strerror, ArmV8RBESysVModel):
    pass


class ArmV8RBESysVStrlen(Strlen, ArmV8RBESysVModel):
    pass


__all__ = [
    "ArmV8RBESysVMemcpy",
    "ArmV8RBESysVMemmove",
    "ArmV8RBESysVStrcpy",
    "ArmV8RBESysVStrncpy",
    "ArmV8RBESysVStrcat",
    "ArmV8RBESysVStrncat",
    "ArmV8RBESysVMemcmp",
    "ArmV8RBESysVStrncmp",
    "ArmV8RBESysVStrcmp",
    "ArmV8RBESysVStrcoll",
    "ArmV8RBESysVStrxfrm",
    "ArmV8RBESysVMemchr",
    "ArmV8RBESysVStrchr",
    "ArmV8RBESysVStrcspn",
    "ArmV8RBESysVStrpbrk",
    "ArmV8RBESysVStrrchr",
    "ArmV8RBESysVStrspn",
    "ArmV8RBESysVStrstr",
    "ArmV8RBESysVStrtok",
    "ArmV8RBESysVMemset",
    "ArmV8RBESysVStrerror",
    "ArmV8RBESysVStrlen",
]
