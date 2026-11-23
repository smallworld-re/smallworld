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
from ..systemv import ArmV7ABESysVModel


class ArmV7ABESysVMemcpy(Memcpy, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVMemmove(Memmove, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrcpy(Strcpy, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrncpy(Strncpy, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrcat(Strcat, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrncat(Strncat, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVMemcmp(Memcmp, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrncmp(Strncmp, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrcmp(Strcmp, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrcoll(Strcoll, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrxfrm(Strxfrm, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVMemchr(Memchr, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrchr(Strchr, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrcspn(Strcspn, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrpbrk(Strpbrk, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrrchr(Strrchr, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrspn(Strspn, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrstr(Strstr, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrtok(Strtok, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVMemset(Memset, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrerror(Strerror, ArmV7ABESysVModel):
    pass


class ArmV7ABESysVStrlen(Strlen, ArmV7ABESysVModel):
    pass


__all__ = [
    "ArmV7ABESysVMemcpy",
    "ArmV7ABESysVMemmove",
    "ArmV7ABESysVStrcpy",
    "ArmV7ABESysVStrncpy",
    "ArmV7ABESysVStrcat",
    "ArmV7ABESysVStrncat",
    "ArmV7ABESysVMemcmp",
    "ArmV7ABESysVStrncmp",
    "ArmV7ABESysVStrcmp",
    "ArmV7ABESysVStrcoll",
    "ArmV7ABESysVStrxfrm",
    "ArmV7ABESysVMemchr",
    "ArmV7ABESysVStrchr",
    "ArmV7ABESysVStrcspn",
    "ArmV7ABESysVStrpbrk",
    "ArmV7ABESysVStrrchr",
    "ArmV7ABESysVStrspn",
    "ArmV7ABESysVStrstr",
    "ArmV7ABESysVStrtok",
    "ArmV7ABESysVMemset",
    "ArmV7ABESysVStrerror",
    "ArmV7ABESysVStrlen",
]
