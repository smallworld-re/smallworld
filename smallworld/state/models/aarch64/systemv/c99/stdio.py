from ....c99 import (
    Fclose,
    Feof,
    Ferror,
    Fgetc,
    Fgets,
    Fopen,
    Fprintf,
    Fputc,
    Fputs,
    Fread,
    Fscanf,
    Fseek,
    Ftell,
    Fwrite,
    Getc,
    Getchar,
    Printf,
    Putc,
    Putchar,
    Puts,
    Remove,
    Rename,
    Rewind,
    Scanf,
    Snprintf,
    Sprintf,
    Sscanf,
)
from ..systemv import AArch64SysVModel


class AArch64SysVFclose(Fclose, AArch64SysVModel):
    pass


class AArch64SysVFeof(Feof, AArch64SysVModel):
    pass


class AArch64SysVFerror(Ferror, AArch64SysVModel):
    pass


class AArch64SysVFgetc(Fgetc, AArch64SysVModel):
    pass


class AArch64SysVFgets(Fgets, AArch64SysVModel):
    pass


class AArch64SysVFopen(Fopen, AArch64SysVModel):
    pass


class AArch64SysVFprintf(Fprintf, AArch64SysVModel):
    pass


class AArch64SysVFputc(Fputc, AArch64SysVModel):
    pass


class AArch64SysVFputs(Fputs, AArch64SysVModel):
    pass


class AArch64SysVFread(Fread, AArch64SysVModel):
    pass


class AArch64SysVFscanf(Fscanf, AArch64SysVModel):
    pass


class AArch64SysVFseek(Fseek, AArch64SysVModel):
    pass


class AArch64SysVFtell(Ftell, AArch64SysVModel):
    pass


class AArch64SysVFwrite(Fwrite, AArch64SysVModel):
    pass


class AArch64SysVGetc(Getc, AArch64SysVModel):
    pass


class AArch64SysVGetchar(Getchar, AArch64SysVModel):
    pass


class AArch64SysVPrintf(Printf, AArch64SysVModel):
    pass


class AArch64SysVPutc(Putc, AArch64SysVModel):
    pass


class AArch64SysVPutchar(Putchar, AArch64SysVModel):
    pass


class AArch64SysVPuts(Puts, AArch64SysVModel):
    pass


class AArch64SysVRemove(Remove, AArch64SysVModel):
    pass


class AArch64SysVRename(Rename, AArch64SysVModel):
    pass


class AArch64SysVRewind(Rewind, AArch64SysVModel):
    pass


class AArch64SysVScanf(Scanf, AArch64SysVModel):
    pass


class AArch64SysVSnprintf(Snprintf, AArch64SysVModel):
    pass


class AArch64SysVSprintf(Sprintf, AArch64SysVModel):
    pass


class AArch64SysVSscanf(Sscanf, AArch64SysVModel):
    pass


__all__ = [
    "AArch64SysVFclose",
    "AArch64SysVFeof",
    "AArch64SysVFerror",
    "AArch64SysVFgetc",
    "AArch64SysVFgets",
    "AArch64SysVFopen",
    "AArch64SysVFprintf",
    "AArch64SysVFputc",
    "AArch64SysVFputs",
    "AArch64SysVFread",
    "AArch64SysVFscanf",
    "AArch64SysVFseek",
    "AArch64SysVFtell",
    "AArch64SysVFwrite",
    "AArch64SysVGetc",
    "AArch64SysVGetchar",
    "AArch64SysVPrintf",
    "AArch64SysVPutc",
    "AArch64SysVPutchar",
    "AArch64SysVPuts",
    "AArch64SysVRemove",
    "AArch64SysVRename",
    "AArch64SysVRewind",
    "AArch64SysVScanf",
    "AArch64SysVSnprintf",
    "AArch64SysVSprintf",
    "AArch64SysVSscanf",
]
