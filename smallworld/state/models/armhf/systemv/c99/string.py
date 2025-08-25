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
from ..systemv import ArmHFSysVModel


class ArmHFSysVMemcpy(Memcpy, ArmHFSysVModel):
    pass


class ArmHFSysVMemmove(Memmove, ArmHFSysVModel):
    pass


class ArmHFSysVStrcpy(Strcpy, ArmHFSysVModel):
    pass


class ArmHFSysVStrncpy(Strncpy, ArmHFSysVModel):
    pass


class ArmHFSysVStrcat(Strcat, ArmHFSysVModel):
    pass


class ArmHFSysVStrncat(Strncat, ArmHFSysVModel):
    pass


class ArmHFSysVMemcmp(Memcmp, ArmHFSysVModel):
    pass


class ArmHFSysVStrncmp(Strncmp, ArmHFSysVModel):
    pass


class ArmHFSysVStrcmp(Strcmp, ArmHFSysVModel):
    pass


class ArmHFSysVStrcoll(Strcoll, ArmHFSysVModel):
    pass


class ArmHFSysVStrxfrm(Strxfrm, ArmHFSysVModel):
    pass


class ArmHFSysVMemchr(Memchr, ArmHFSysVModel):
    pass


class ArmHFSysVStrchr(Strchr, ArmHFSysVModel):
    pass


class ArmHFSysVStrcspn(Strcspn, ArmHFSysVModel):
    pass


class ArmHFSysVStrpbrk(Strpbrk, ArmHFSysVModel):
    pass


class ArmHFSysVStrrchr(Strrchr, ArmHFSysVModel):
    pass


class ArmHFSysVStrspn(Strspn, ArmHFSysVModel):
    pass


class ArmHFSysVStrstr(Strstr, ArmHFSysVModel):
    pass


class ArmHFSysVStrtok(Strtok, ArmHFSysVModel):
    pass


class ArmHFSysVMemset(Memset, ArmHFSysVModel):
    pass


class ArmHFSysVStrerror(Strerror, ArmHFSysVModel):
    pass


class ArmHFSysVStrlen(Strlen, ArmHFSysVModel):
    pass


__all__ = [
    "ArmHFSysVMemcpy",
    "ArmHFSysVMemmove",
    "ArmHFSysVStrcpy",
    "ArmHFSysVStrncpy",
    "ArmHFSysVStrcat",
    "ArmHFSysVStrncat",
    "ArmHFSysVMemcmp",
    "ArmHFSysVStrncmp",
    "ArmHFSysVStrcmp",
    "ArmHFSysVStrcoll",
    "ArmHFSysVStrxfrm",
    "ArmHFSysVMemchr",
    "ArmHFSysVStrchr",
    "ArmHFSysVStrcspn",
    "ArmHFSysVStrpbrk",
    "ArmHFSysVStrrchr",
    "ArmHFSysVStrspn",
    "ArmHFSysVStrstr",
    "ArmHFSysVStrtok",
    "ArmHFSysVMemset",
    "ArmHFSysVStrerror",
    "ArmHFSysVStrlen",
]
