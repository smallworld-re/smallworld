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
from ..systemv import ArmV7RBESysVModel


class ArmV7RBESysVMemcpy(Memcpy, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVMemmove(Memmove, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrcpy(Strcpy, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrncpy(Strncpy, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrcat(Strcat, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrncat(Strncat, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVMemcmp(Memcmp, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrncmp(Strncmp, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrcmp(Strcmp, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrcoll(Strcoll, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrxfrm(Strxfrm, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVMemchr(Memchr, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrchr(Strchr, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrcspn(Strcspn, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrpbrk(Strpbrk, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrrchr(Strrchr, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrspn(Strspn, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrstr(Strstr, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrtok(Strtok, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVMemset(Memset, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrerror(Strerror, ArmV7RBESysVModel):
    pass


class ArmV7RBESysVStrlen(Strlen, ArmV7RBESysVModel):
    pass


__all__ = [
    "ArmV7RBESysVMemcpy",
    "ArmV7RBESysVMemmove",
    "ArmV7RBESysVStrcpy",
    "ArmV7RBESysVStrncpy",
    "ArmV7RBESysVStrcat",
    "ArmV7RBESysVStrncat",
    "ArmV7RBESysVMemcmp",
    "ArmV7RBESysVStrncmp",
    "ArmV7RBESysVStrcmp",
    "ArmV7RBESysVStrcoll",
    "ArmV7RBESysVStrxfrm",
    "ArmV7RBESysVMemchr",
    "ArmV7RBESysVStrchr",
    "ArmV7RBESysVStrcspn",
    "ArmV7RBESysVStrpbrk",
    "ArmV7RBESysVStrrchr",
    "ArmV7RBESysVStrspn",
    "ArmV7RBESysVStrstr",
    "ArmV7RBESysVStrtok",
    "ArmV7RBESysVMemset",
    "ArmV7RBESysVStrerror",
    "ArmV7RBESysVStrlen",
]
