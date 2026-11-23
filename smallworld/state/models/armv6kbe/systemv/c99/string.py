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
from ..systemv import ArmV6KBESysVModel


class ArmV6KBESysVMemcpy(Memcpy, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVMemmove(Memmove, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrcpy(Strcpy, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrncpy(Strncpy, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrcat(Strcat, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrncat(Strncat, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVMemcmp(Memcmp, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrncmp(Strncmp, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrcmp(Strcmp, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrcoll(Strcoll, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrxfrm(Strxfrm, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVMemchr(Memchr, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrchr(Strchr, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrcspn(Strcspn, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrpbrk(Strpbrk, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrrchr(Strrchr, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrspn(Strspn, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrstr(Strstr, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrtok(Strtok, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVMemset(Memset, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrerror(Strerror, ArmV6KBESysVModel):
    pass


class ArmV6KBESysVStrlen(Strlen, ArmV6KBESysVModel):
    pass


__all__ = [
    "ArmV6KBESysVMemcpy",
    "ArmV6KBESysVMemmove",
    "ArmV6KBESysVStrcpy",
    "ArmV6KBESysVStrncpy",
    "ArmV6KBESysVStrcat",
    "ArmV6KBESysVStrncat",
    "ArmV6KBESysVMemcmp",
    "ArmV6KBESysVStrncmp",
    "ArmV6KBESysVStrcmp",
    "ArmV6KBESysVStrcoll",
    "ArmV6KBESysVStrxfrm",
    "ArmV6KBESysVMemchr",
    "ArmV6KBESysVStrchr",
    "ArmV6KBESysVStrcspn",
    "ArmV6KBESysVStrpbrk",
    "ArmV6KBESysVStrrchr",
    "ArmV6KBESysVStrspn",
    "ArmV6KBESysVStrstr",
    "ArmV6KBESysVStrtok",
    "ArmV6KBESysVMemset",
    "ArmV6KBESysVStrerror",
    "ArmV6KBESysVStrlen",
]
