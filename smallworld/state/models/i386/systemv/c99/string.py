from ...c99 import (
    Memchr,
    Memcmp,
    Memcpy,
    Memmove,
    Memset,
    Strcat,
    Strchr,
    Strcmp,
    Strcoll,
    Strcspn,
    Strerror,
    Strlen,
    Strncat,
    Strncmp,
    Strpbrk,
    Strrchr,
    Strspn,
    Strstr,
    Strtok,
    Strxfrm,
)
from ..systemv import I386SysVModel


class I386SysVMemcpy(Memcpy, I386SysVModel):
    pass


class I386SysVMemmove(Memmove, I386SysVModel):
    pass


class I386SysVStrcat(Strcat, I386SysVModel):
    pass


class I386SysVStrncat(Strncat, I386SysVModel):
    pass


class I386SysVMemcmp(Memcmp, I386SysVModel):
    pass


class I386SysVStrncmp(Strncmp, I386SysVModel):
    pass


class I386SysVStrcmp(Strcmp, I386SysVModel):
    pass


class I386SysVStrcoll(Strcoll, I386SysVModel):
    pass


class I386SysVStrxfrm(Strxfrm, I386SysVModel):
    pass


class I386SysVMemchr(Memchr, I386SysVModel):
    pass


class I386SysVStrchr(Strchr, I386SysVModel):
    pass


class I386SysVStrcspn(Strcspn, I386SysVModel):
    pass


class I386SysVStrpbrk(Strpbrk, I386SysVModel):
    pass


class I386SysVStrrchr(Strrchr, I386SysVModel):
    pass


class I386SysVStrspn(Strspn, I386SysVModel):
    pass


class I386SysVStrstr(Strstr, I386SysVModel):
    pass


class I386SysVStrtok(Strtok, I386SysVModel):
    pass


class I386SysVMemset(Memset, I386SysVModel):
    pass


class I386SysVStrerror(Strerror, I386SysVModel):
    pass


class I386SysVStrlen(Strlen, I386SysVModel):
    pass


__all__ = [
    "I386SysVMemcpy",
    "I386SysVMemmove",
    "I386SysVStrcat",
    "I386SysVStrncat",
    "I386SysVMemcmp",
    "I386SysVStrncmp",
    "I386SysVStrcmp",
    "I386SysVStrcoll",
    "I386SysVStrxfrm",
    "I386SysVMemchr",
    "I386SysVStrchr",
    "I386SysVStrcspn",
    "I386SysVStrpbrk",
    "I386SysVStrrchr",
    "I386SysVStrspn",
    "I386SysVStrstr",
    "I386SysVStrtok",
    "I386SysVMemset",
    "I386SysVStrerror",
    "I386SysVStrlen",
]
