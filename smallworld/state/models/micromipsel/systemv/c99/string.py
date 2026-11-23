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
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVMemcpy(Memcpy, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVMemmove(Memmove, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrcpy(Strcpy, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrncpy(Strncpy, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrcat(Strcat, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrncat(Strncat, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVMemcmp(Memcmp, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrncmp(Strncmp, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrcmp(Strcmp, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrcoll(Strcoll, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrxfrm(Strxfrm, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVMemchr(Memchr, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrchr(Strchr, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrcspn(Strcspn, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrpbrk(Strpbrk, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrrchr(Strrchr, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrspn(Strspn, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrstr(Strstr, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrtok(Strtok, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVMemset(Memset, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrerror(Strerror, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVStrlen(Strlen, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVMemcpy",
    "MicroMIPSELSysVMemmove",
    "MicroMIPSELSysVStrcpy",
    "MicroMIPSELSysVStrncpy",
    "MicroMIPSELSysVStrcat",
    "MicroMIPSELSysVStrncat",
    "MicroMIPSELSysVMemcmp",
    "MicroMIPSELSysVStrncmp",
    "MicroMIPSELSysVStrcmp",
    "MicroMIPSELSysVStrcoll",
    "MicroMIPSELSysVStrxfrm",
    "MicroMIPSELSysVMemchr",
    "MicroMIPSELSysVStrchr",
    "MicroMIPSELSysVStrcspn",
    "MicroMIPSELSysVStrpbrk",
    "MicroMIPSELSysVStrrchr",
    "MicroMIPSELSysVStrspn",
    "MicroMIPSELSysVStrstr",
    "MicroMIPSELSysVStrtok",
    "MicroMIPSELSysVMemset",
    "MicroMIPSELSysVStrerror",
    "MicroMIPSELSysVStrlen",
]
