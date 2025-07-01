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
from ..systemv import PowerPCSysVModel


class PowerPCSysVMemcpy(Memcpy, PowerPCSysVModel):
    pass


class PowerPCSysVMemmove(Memmove, PowerPCSysVModel):
    pass


class PowerPCSysVStrcat(Strcat, PowerPCSysVModel):
    pass


class PowerPCSysVStrncat(Strncat, PowerPCSysVModel):
    pass


class PowerPCSysVMemcmp(Memcmp, PowerPCSysVModel):
    pass


class PowerPCSysVStrncmp(Strncmp, PowerPCSysVModel):
    pass


class PowerPCSysVStrcmp(Strcmp, PowerPCSysVModel):
    pass


class PowerPCSysVStrcoll(Strcoll, PowerPCSysVModel):
    pass


class PowerPCSysVStrxfrm(Strxfrm, PowerPCSysVModel):
    pass


class PowerPCSysVMemchr(Memchr, PowerPCSysVModel):
    pass


class PowerPCSysVStrchr(Strchr, PowerPCSysVModel):
    pass


class PowerPCSysVStrcspn(Strcspn, PowerPCSysVModel):
    pass


class PowerPCSysVStrpbrk(Strpbrk, PowerPCSysVModel):
    pass


class PowerPCSysVStrrchr(Strrchr, PowerPCSysVModel):
    pass


class PowerPCSysVStrspn(Strspn, PowerPCSysVModel):
    pass


class PowerPCSysVStrstr(Strstr, PowerPCSysVModel):
    pass


class PowerPCSysVStrtok(Strtok, PowerPCSysVModel):
    pass


class PowerPCSysVMemset(Memset, PowerPCSysVModel):
    pass


class PowerPCSysVStrerror(Strerror, PowerPCSysVModel):
    pass


class PowerPCSysVStrlen(Strlen, PowerPCSysVModel):
    pass


__all__ = [
    "PowerPCSysVMemcpy",
    "PowerPCSysVMemmove",
    "PowerPCSysVStrcat",
    "PowerPCSysVStrncat",
    "PowerPCSysVMemcmp",
    "PowerPCSysVStrncmp",
    "PowerPCSysVStrcmp",
    "PowerPCSysVStrcoll",
    "PowerPCSysVStrxfrm",
    "PowerPCSysVMemchr",
    "PowerPCSysVStrchr",
    "PowerPCSysVStrcspn",
    "PowerPCSysVStrpbrk",
    "PowerPCSysVStrrchr",
    "PowerPCSysVStrspn",
    "PowerPCSysVStrstr",
    "PowerPCSysVStrtok",
    "PowerPCSysVMemset",
    "PowerPCSysVStrerror",
    "PowerPCSysVStrlen",
]
