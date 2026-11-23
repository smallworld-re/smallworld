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
from ..systemv import SPARC32SysVModel


class SPARC32SysVMemcpy(Memcpy, SPARC32SysVModel):
    pass


class SPARC32SysVMemmove(Memmove, SPARC32SysVModel):
    pass


class SPARC32SysVStrcpy(Strcpy, SPARC32SysVModel):
    pass


class SPARC32SysVStrncpy(Strncpy, SPARC32SysVModel):
    pass


class SPARC32SysVStrcat(Strcat, SPARC32SysVModel):
    pass


class SPARC32SysVStrncat(Strncat, SPARC32SysVModel):
    pass


class SPARC32SysVMemcmp(Memcmp, SPARC32SysVModel):
    pass


class SPARC32SysVStrncmp(Strncmp, SPARC32SysVModel):
    pass


class SPARC32SysVStrcmp(Strcmp, SPARC32SysVModel):
    pass


class SPARC32SysVStrcoll(Strcoll, SPARC32SysVModel):
    pass


class SPARC32SysVStrxfrm(Strxfrm, SPARC32SysVModel):
    pass


class SPARC32SysVMemchr(Memchr, SPARC32SysVModel):
    pass


class SPARC32SysVStrchr(Strchr, SPARC32SysVModel):
    pass


class SPARC32SysVStrcspn(Strcspn, SPARC32SysVModel):
    pass


class SPARC32SysVStrpbrk(Strpbrk, SPARC32SysVModel):
    pass


class SPARC32SysVStrrchr(Strrchr, SPARC32SysVModel):
    pass


class SPARC32SysVStrspn(Strspn, SPARC32SysVModel):
    pass


class SPARC32SysVStrstr(Strstr, SPARC32SysVModel):
    pass


class SPARC32SysVStrtok(Strtok, SPARC32SysVModel):
    pass


class SPARC32SysVMemset(Memset, SPARC32SysVModel):
    pass


class SPARC32SysVStrerror(Strerror, SPARC32SysVModel):
    pass


class SPARC32SysVStrlen(Strlen, SPARC32SysVModel):
    pass


__all__ = [
    "SPARC32SysVMemcpy",
    "SPARC32SysVMemmove",
    "SPARC32SysVStrcpy",
    "SPARC32SysVStrncpy",
    "SPARC32SysVStrcat",
    "SPARC32SysVStrncat",
    "SPARC32SysVMemcmp",
    "SPARC32SysVStrncmp",
    "SPARC32SysVStrcmp",
    "SPARC32SysVStrcoll",
    "SPARC32SysVStrxfrm",
    "SPARC32SysVMemchr",
    "SPARC32SysVStrchr",
    "SPARC32SysVStrcspn",
    "SPARC32SysVStrpbrk",
    "SPARC32SysVStrrchr",
    "SPARC32SysVStrspn",
    "SPARC32SysVStrstr",
    "SPARC32SysVStrtok",
    "SPARC32SysVMemset",
    "SPARC32SysVStrerror",
    "SPARC32SysVStrlen",
]
