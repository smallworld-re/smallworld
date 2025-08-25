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
from ..systemv import RiscV64SysVModel


class RiscV64SysVMemcpy(Memcpy, RiscV64SysVModel):
    pass


class RiscV64SysVMemmove(Memmove, RiscV64SysVModel):
    pass


class RiscV64SysVStrcpy(Strcpy, RiscV64SysVModel):
    pass


class RiscV64SysVStrncpy(Strncpy, RiscV64SysVModel):
    pass


class RiscV64SysVStrcat(Strcat, RiscV64SysVModel):
    pass


class RiscV64SysVStrncat(Strncat, RiscV64SysVModel):
    pass


class RiscV64SysVMemcmp(Memcmp, RiscV64SysVModel):
    pass


class RiscV64SysVStrncmp(Strncmp, RiscV64SysVModel):
    pass


class RiscV64SysVStrcmp(Strcmp, RiscV64SysVModel):
    pass


class RiscV64SysVStrcoll(Strcoll, RiscV64SysVModel):
    pass


class RiscV64SysVStrxfrm(Strxfrm, RiscV64SysVModel):
    pass


class RiscV64SysVMemchr(Memchr, RiscV64SysVModel):
    pass


class RiscV64SysVStrchr(Strchr, RiscV64SysVModel):
    pass


class RiscV64SysVStrcspn(Strcspn, RiscV64SysVModel):
    pass


class RiscV64SysVStrpbrk(Strpbrk, RiscV64SysVModel):
    pass


class RiscV64SysVStrrchr(Strrchr, RiscV64SysVModel):
    pass


class RiscV64SysVStrspn(Strspn, RiscV64SysVModel):
    pass


class RiscV64SysVStrstr(Strstr, RiscV64SysVModel):
    pass


class RiscV64SysVStrtok(Strtok, RiscV64SysVModel):
    pass


class RiscV64SysVMemset(Memset, RiscV64SysVModel):
    pass


class RiscV64SysVStrerror(Strerror, RiscV64SysVModel):
    pass


class RiscV64SysVStrlen(Strlen, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVMemcpy",
    "RiscV64SysVMemmove",
    "RiscV64SysVStrcpy",
    "RiscV64SysVStrncpy",
    "RiscV64SysVStrcat",
    "RiscV64SysVStrncat",
    "RiscV64SysVMemcmp",
    "RiscV64SysVStrncmp",
    "RiscV64SysVStrcmp",
    "RiscV64SysVStrcoll",
    "RiscV64SysVStrxfrm",
    "RiscV64SysVMemchr",
    "RiscV64SysVStrchr",
    "RiscV64SysVStrcspn",
    "RiscV64SysVStrpbrk",
    "RiscV64SysVStrrchr",
    "RiscV64SysVStrspn",
    "RiscV64SysVStrstr",
    "RiscV64SysVStrtok",
    "RiscV64SysVMemset",
    "RiscV64SysVStrerror",
    "RiscV64SysVStrlen",
]
