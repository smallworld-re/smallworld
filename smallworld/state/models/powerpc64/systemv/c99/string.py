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
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVMemcpy(Memcpy, PowerPC64SysVModel):
    pass


class PowerPC64SysVMemmove(Memmove, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrcpy(Strcpy, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrncpy(Strncpy, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrcat(Strcat, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrncat(Strncat, PowerPC64SysVModel):
    pass


class PowerPC64SysVMemcmp(Memcmp, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrncmp(Strncmp, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrcmp(Strcmp, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrcoll(Strcoll, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrxfrm(Strxfrm, PowerPC64SysVModel):
    pass


class PowerPC64SysVMemchr(Memchr, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrchr(Strchr, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrcspn(Strcspn, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrpbrk(Strpbrk, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrrchr(Strrchr, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrspn(Strspn, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrstr(Strstr, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrtok(Strtok, PowerPC64SysVModel):
    pass


class PowerPC64SysVMemset(Memset, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrerror(Strerror, PowerPC64SysVModel):
    pass


class PowerPC64SysVStrlen(Strlen, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVMemcpy",
    "PowerPC64SysVMemmove",
    "PowerPC64SysVStrcpy",
    "PowerPC64SysVStrncpy",
    "PowerPC64SysVStrcat",
    "PowerPC64SysVStrncat",
    "PowerPC64SysVMemcmp",
    "PowerPC64SysVStrncmp",
    "PowerPC64SysVStrcmp",
    "PowerPC64SysVStrcoll",
    "PowerPC64SysVStrxfrm",
    "PowerPC64SysVMemchr",
    "PowerPC64SysVStrchr",
    "PowerPC64SysVStrcspn",
    "PowerPC64SysVStrpbrk",
    "PowerPC64SysVStrrchr",
    "PowerPC64SysVStrspn",
    "PowerPC64SysVStrstr",
    "PowerPC64SysVStrtok",
    "PowerPC64SysVMemset",
    "PowerPC64SysVStrerror",
    "PowerPC64SysVStrlen",
]
