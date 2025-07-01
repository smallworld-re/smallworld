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
from ..systemv import AMD64SysVModel


class AMD64SysVMemcpy(Memcpy, AMD64SysVModel):
    pass


class AMD64SysVMemmove(Memmove, AMD64SysVModel):
    pass


class AMD64SysVStrcat(Strcat, AMD64SysVModel):
    pass


class AMD64SysVStrncat(Strncat, AMD64SysVModel):
    pass


class AMD64SysVMemcmp(Memcmp, AMD64SysVModel):
    pass


class AMD64SysVStrncmp(Strncmp, AMD64SysVModel):
    pass


class AMD64SysVStrcmp(Strcmp, AMD64SysVModel):
    pass


class AMD64SysVStrcoll(Strcoll, AMD64SysVModel):
    pass


class AMD64SysVStrxfrm(Strxfrm, AMD64SysVModel):
    pass


class AMD64SysVMemchr(Memchr, AMD64SysVModel):
    pass


class AMD64SysVStrchr(Strchr, AMD64SysVModel):
    pass


class AMD64SysVStrcspn(Strcspn, AMD64SysVModel):
    pass


class AMD64SysVStrpbrk(Strpbrk, AMD64SysVModel):
    pass


class AMD64SysVStrrchr(Strrchr, AMD64SysVModel):
    pass


class AMD64SysVStrspn(Strspn, AMD64SysVModel):
    pass


class AMD64SysVStrstr(Strstr, AMD64SysVModel):
    pass


class AMD64SysVStrtok(Strtok, AMD64SysVModel):
    pass


class AMD64SysVMemset(Memset, AMD64SysVModel):
    pass


class AMD64SysVStrerror(Strerror, AMD64SysVModel):
    pass


class AMD64SysVStrlen(Strlen, AMD64SysVModel):
    pass


__all__ = [
    "AMD64SysVMemcpy",
    "AMD64SysVMemmove",
    "AMD64SysVStrcat",
    "AMD64SysVStrncat",
    "AMD64SysVMemcmp",
    "AMD64SysVStrncmp",
    "AMD64SysVStrcmp",
    "AMD64SysVStrcoll",
    "AMD64SysVStrxfrm",
    "AMD64SysVMemchr",
    "AMD64SysVStrchr",
    "AMD64SysVStrcspn",
    "AMD64SysVStrpbrk",
    "AMD64SysVStrrchr",
    "AMD64SysVStrspn",
    "AMD64SysVStrstr",
    "AMD64SysVStrtok",
    "AMD64SysVMemset",
    "AMD64SysVStrerror",
    "AMD64SysVStrlen",
]
