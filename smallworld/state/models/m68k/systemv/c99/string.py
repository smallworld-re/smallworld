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
from ..systemv import M68KSysVModel


class M68KSysVMemcpy(Memcpy, M68KSysVModel):
    pass


class M68KSysVMemmove(Memmove, M68KSysVModel):
    pass


class M68KSysVStrcpy(Strcpy, M68KSysVModel):
    pass


class M68KSysVStrncpy(Strncpy, M68KSysVModel):
    pass


class M68KSysVStrcat(Strcat, M68KSysVModel):
    pass


class M68KSysVStrncat(Strncat, M68KSysVModel):
    pass


class M68KSysVMemcmp(Memcmp, M68KSysVModel):
    pass


class M68KSysVStrncmp(Strncmp, M68KSysVModel):
    pass


class M68KSysVStrcmp(Strcmp, M68KSysVModel):
    pass


class M68KSysVStrcoll(Strcoll, M68KSysVModel):
    pass


class M68KSysVStrxfrm(Strxfrm, M68KSysVModel):
    pass


class M68KSysVMemchr(Memchr, M68KSysVModel):
    pass


class M68KSysVStrchr(Strchr, M68KSysVModel):
    pass


class M68KSysVStrcspn(Strcspn, M68KSysVModel):
    pass


class M68KSysVStrpbrk(Strpbrk, M68KSysVModel):
    pass


class M68KSysVStrrchr(Strrchr, M68KSysVModel):
    pass


class M68KSysVStrspn(Strspn, M68KSysVModel):
    pass


class M68KSysVStrstr(Strstr, M68KSysVModel):
    pass


class M68KSysVStrtok(Strtok, M68KSysVModel):
    pass


class M68KSysVMemset(Memset, M68KSysVModel):
    pass


class M68KSysVStrerror(Strerror, M68KSysVModel):
    pass


class M68KSysVStrlen(Strlen, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVMemcpy",
    "M68KSysVMemmove",
    "M68KSysVStrcpy",
    "M68KSysVStrncpy",
    "M68KSysVStrcat",
    "M68KSysVStrncat",
    "M68KSysVMemcmp",
    "M68KSysVStrncmp",
    "M68KSysVStrcmp",
    "M68KSysVStrcoll",
    "M68KSysVStrxfrm",
    "M68KSysVMemchr",
    "M68KSysVStrchr",
    "M68KSysVStrcspn",
    "M68KSysVStrpbrk",
    "M68KSysVStrrchr",
    "M68KSysVStrspn",
    "M68KSysVStrstr",
    "M68KSysVStrtok",
    "M68KSysVMemset",
    "M68KSysVStrerror",
    "M68KSysVStrlen",
]
