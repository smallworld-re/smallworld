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
from ..systemv import LoongArch64SysVModel


class LoongArch64SysVMemcpy(Memcpy, LoongArch64SysVModel):
    pass


class LoongArch64SysVMemmove(Memmove, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrcpy(Strcpy, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrncpy(Strncpy, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrcat(Strcat, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrncat(Strncat, LoongArch64SysVModel):
    pass


class LoongArch64SysVMemcmp(Memcmp, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrncmp(Strncmp, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrcmp(Strcmp, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrcoll(Strcoll, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrxfrm(Strxfrm, LoongArch64SysVModel):
    pass


class LoongArch64SysVMemchr(Memchr, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrchr(Strchr, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrcspn(Strcspn, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrpbrk(Strpbrk, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrrchr(Strrchr, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrspn(Strspn, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrstr(Strstr, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrtok(Strtok, LoongArch64SysVModel):
    pass


class LoongArch64SysVMemset(Memset, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrerror(Strerror, LoongArch64SysVModel):
    pass


class LoongArch64SysVStrlen(Strlen, LoongArch64SysVModel):
    pass


__all__ = [
    "LoongArch64SysVMemcpy",
    "LoongArch64SysVMemmove",
    "LoongArch64SysVStrcpy",
    "LoongArch64SysVStrncpy",
    "LoongArch64SysVStrcat",
    "LoongArch64SysVStrncat",
    "LoongArch64SysVMemcmp",
    "LoongArch64SysVStrncmp",
    "LoongArch64SysVStrcmp",
    "LoongArch64SysVStrcoll",
    "LoongArch64SysVStrxfrm",
    "LoongArch64SysVMemchr",
    "LoongArch64SysVStrchr",
    "LoongArch64SysVStrcspn",
    "LoongArch64SysVStrpbrk",
    "LoongArch64SysVStrrchr",
    "LoongArch64SysVStrspn",
    "LoongArch64SysVStrstr",
    "LoongArch64SysVStrtok",
    "LoongArch64SysVMemset",
    "LoongArch64SysVStrerror",
    "LoongArch64SysVStrlen",
]
