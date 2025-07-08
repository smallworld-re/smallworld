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
from ..systemv import MIPS64SysVModel


class MIPS64SysVMemcpy(Memcpy, MIPS64SysVModel):
    pass


class MIPS64SysVMemmove(Memmove, MIPS64SysVModel):
    pass


class MIPS64SysVStrcpy(Strcpy, MIPS64SysVModel):
    pass


class MIPS64SysVStrncpy(Strncpy, MIPS64SysVModel):
    pass


class MIPS64SysVStrcat(Strcat, MIPS64SysVModel):
    pass


class MIPS64SysVStrncat(Strncat, MIPS64SysVModel):
    pass


class MIPS64SysVMemcmp(Memcmp, MIPS64SysVModel):
    pass


class MIPS64SysVStrncmp(Strncmp, MIPS64SysVModel):
    pass


class MIPS64SysVStrcmp(Strcmp, MIPS64SysVModel):
    pass


class MIPS64SysVStrcoll(Strcoll, MIPS64SysVModel):
    pass


class MIPS64SysVStrxfrm(Strxfrm, MIPS64SysVModel):
    pass


class MIPS64SysVMemchr(Memchr, MIPS64SysVModel):
    pass


class MIPS64SysVStrchr(Strchr, MIPS64SysVModel):
    pass


class MIPS64SysVStrcspn(Strcspn, MIPS64SysVModel):
    pass


class MIPS64SysVStrpbrk(Strpbrk, MIPS64SysVModel):
    pass


class MIPS64SysVStrrchr(Strrchr, MIPS64SysVModel):
    pass


class MIPS64SysVStrspn(Strspn, MIPS64SysVModel):
    pass


class MIPS64SysVStrstr(Strstr, MIPS64SysVModel):
    pass


class MIPS64SysVStrtok(Strtok, MIPS64SysVModel):
    pass


class MIPS64SysVMemset(Memset, MIPS64SysVModel):
    pass


class MIPS64SysVStrerror(Strerror, MIPS64SysVModel):
    pass


class MIPS64SysVStrlen(Strlen, MIPS64SysVModel):
    pass


__all__ = [
    "MIPS64SysVMemcpy",
    "MIPS64SysVMemmove",
    "MIPS64SysVStrcpy",
    "MIPS64SysVStrncpy",
    "MIPS64SysVStrcat",
    "MIPS64SysVStrncat",
    "MIPS64SysVMemcmp",
    "MIPS64SysVStrncmp",
    "MIPS64SysVStrcmp",
    "MIPS64SysVStrcoll",
    "MIPS64SysVStrxfrm",
    "MIPS64SysVMemchr",
    "MIPS64SysVStrchr",
    "MIPS64SysVStrcspn",
    "MIPS64SysVStrpbrk",
    "MIPS64SysVStrrchr",
    "MIPS64SysVStrspn",
    "MIPS64SysVStrstr",
    "MIPS64SysVStrtok",
    "MIPS64SysVMemset",
    "MIPS64SysVStrerror",
    "MIPS64SysVStrlen",
]
