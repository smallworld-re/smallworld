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
from ..systemv import MIPSELSysVModel


class MIPSELSysVMemcpy(Memcpy, MIPSELSysVModel):
    pass


class MIPSELSysVMemmove(Memmove, MIPSELSysVModel):
    pass


class MIPSELSysVStrcpy(Strcpy, MIPSELSysVModel):
    pass


class MIPSELSysVStrncpy(Strncpy, MIPSELSysVModel):
    pass


class MIPSELSysVStrcat(Strcat, MIPSELSysVModel):
    pass


class MIPSELSysVStrncat(Strncat, MIPSELSysVModel):
    pass


class MIPSELSysVMemcmp(Memcmp, MIPSELSysVModel):
    pass


class MIPSELSysVStrncmp(Strncmp, MIPSELSysVModel):
    pass


class MIPSELSysVStrcmp(Strcmp, MIPSELSysVModel):
    pass


class MIPSELSysVStrcoll(Strcoll, MIPSELSysVModel):
    pass


class MIPSELSysVStrxfrm(Strxfrm, MIPSELSysVModel):
    pass


class MIPSELSysVMemchr(Memchr, MIPSELSysVModel):
    pass


class MIPSELSysVStrchr(Strchr, MIPSELSysVModel):
    pass


class MIPSELSysVStrcspn(Strcspn, MIPSELSysVModel):
    pass


class MIPSELSysVStrpbrk(Strpbrk, MIPSELSysVModel):
    pass


class MIPSELSysVStrrchr(Strrchr, MIPSELSysVModel):
    pass


class MIPSELSysVStrspn(Strspn, MIPSELSysVModel):
    pass


class MIPSELSysVStrstr(Strstr, MIPSELSysVModel):
    pass


class MIPSELSysVStrtok(Strtok, MIPSELSysVModel):
    pass


class MIPSELSysVMemset(Memset, MIPSELSysVModel):
    pass


class MIPSELSysVStrerror(Strerror, MIPSELSysVModel):
    pass


class MIPSELSysVStrlen(Strlen, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVMemcpy",
    "MIPSELSysVMemmove",
    "MIPSELSysVStrcpy",
    "MIPSELSysVStrncpy",
    "MIPSELSysVStrcat",
    "MIPSELSysVStrncat",
    "MIPSELSysVMemcmp",
    "MIPSELSysVStrncmp",
    "MIPSELSysVStrcmp",
    "MIPSELSysVStrcoll",
    "MIPSELSysVStrxfrm",
    "MIPSELSysVMemchr",
    "MIPSELSysVStrchr",
    "MIPSELSysVStrcspn",
    "MIPSELSysVStrpbrk",
    "MIPSELSysVStrrchr",
    "MIPSELSysVStrspn",
    "MIPSELSysVStrstr",
    "MIPSELSysVStrtok",
    "MIPSELSysVMemset",
    "MIPSELSysVStrerror",
    "MIPSELSysVStrlen",
]
