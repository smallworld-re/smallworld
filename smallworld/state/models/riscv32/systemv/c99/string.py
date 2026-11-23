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
from ..systemv import RiscV32SysVModel


class RiscV32SysVMemcpy(Memcpy, RiscV32SysVModel):
    pass


class RiscV32SysVMemmove(Memmove, RiscV32SysVModel):
    pass


class RiscV32SysVStrcpy(Strcpy, RiscV32SysVModel):
    pass


class RiscV32SysVStrncpy(Strncpy, RiscV32SysVModel):
    pass


class RiscV32SysVStrcat(Strcat, RiscV32SysVModel):
    pass


class RiscV32SysVStrncat(Strncat, RiscV32SysVModel):
    pass


class RiscV32SysVMemcmp(Memcmp, RiscV32SysVModel):
    pass


class RiscV32SysVStrncmp(Strncmp, RiscV32SysVModel):
    pass


class RiscV32SysVStrcmp(Strcmp, RiscV32SysVModel):
    pass


class RiscV32SysVStrcoll(Strcoll, RiscV32SysVModel):
    pass


class RiscV32SysVStrxfrm(Strxfrm, RiscV32SysVModel):
    pass


class RiscV32SysVMemchr(Memchr, RiscV32SysVModel):
    pass


class RiscV32SysVStrchr(Strchr, RiscV32SysVModel):
    pass


class RiscV32SysVStrcspn(Strcspn, RiscV32SysVModel):
    pass


class RiscV32SysVStrpbrk(Strpbrk, RiscV32SysVModel):
    pass


class RiscV32SysVStrrchr(Strrchr, RiscV32SysVModel):
    pass


class RiscV32SysVStrspn(Strspn, RiscV32SysVModel):
    pass


class RiscV32SysVStrstr(Strstr, RiscV32SysVModel):
    pass


class RiscV32SysVStrtok(Strtok, RiscV32SysVModel):
    pass


class RiscV32SysVMemset(Memset, RiscV32SysVModel):
    pass


class RiscV32SysVStrerror(Strerror, RiscV32SysVModel):
    pass


class RiscV32SysVStrlen(Strlen, RiscV32SysVModel):
    pass


__all__ = [
    "RiscV32SysVMemcpy",
    "RiscV32SysVMemmove",
    "RiscV32SysVStrcpy",
    "RiscV32SysVStrncpy",
    "RiscV32SysVStrcat",
    "RiscV32SysVStrncat",
    "RiscV32SysVMemcmp",
    "RiscV32SysVStrncmp",
    "RiscV32SysVStrcmp",
    "RiscV32SysVStrcoll",
    "RiscV32SysVStrxfrm",
    "RiscV32SysVMemchr",
    "RiscV32SysVStrchr",
    "RiscV32SysVStrcspn",
    "RiscV32SysVStrpbrk",
    "RiscV32SysVStrrchr",
    "RiscV32SysVStrspn",
    "RiscV32SysVStrstr",
    "RiscV32SysVStrtok",
    "RiscV32SysVMemset",
    "RiscV32SysVStrerror",
    "RiscV32SysVStrlen",
]
