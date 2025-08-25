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
from ..systemv import MIPS64ELSysVModel


class MIPS64ELSysVMemcpy(Memcpy, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVMemmove(Memmove, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrcpy(Strcpy, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrncpy(Strncpy, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrcat(Strcat, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrncat(Strncat, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVMemcmp(Memcmp, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrncmp(Strncmp, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrcmp(Strcmp, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrcoll(Strcoll, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrxfrm(Strxfrm, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVMemchr(Memchr, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrchr(Strchr, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrcspn(Strcspn, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrpbrk(Strpbrk, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrrchr(Strrchr, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrspn(Strspn, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrstr(Strstr, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrtok(Strtok, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVMemset(Memset, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrerror(Strerror, MIPS64ELSysVModel):
    pass


class MIPS64ELSysVStrlen(Strlen, MIPS64ELSysVModel):
    pass


__all__ = [
    "MIPS64ELSysVMemcpy",
    "MIPS64ELSysVMemmove",
    "MIPS64ELSysVStrcpy",
    "MIPS64ELSysVStrncpy",
    "MIPS64ELSysVStrcat",
    "MIPS64ELSysVStrncat",
    "MIPS64ELSysVMemcmp",
    "MIPS64ELSysVStrncmp",
    "MIPS64ELSysVStrcmp",
    "MIPS64ELSysVStrcoll",
    "MIPS64ELSysVStrxfrm",
    "MIPS64ELSysVMemchr",
    "MIPS64ELSysVStrchr",
    "MIPS64ELSysVStrcspn",
    "MIPS64ELSysVStrpbrk",
    "MIPS64ELSysVStrrchr",
    "MIPS64ELSysVStrspn",
    "MIPS64ELSysVStrstr",
    "MIPS64ELSysVStrtok",
    "MIPS64ELSysVMemset",
    "MIPS64ELSysVStrerror",
    "MIPS64ELSysVStrlen",
]
