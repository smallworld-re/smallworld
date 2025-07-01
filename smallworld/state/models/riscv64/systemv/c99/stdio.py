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
from ..systemv import RiscV64SysVModel


class RiscV64SysVFclose(Fclose, RiscV64SysVModel):
    pass


class RiscV64SysVFeof(Feof, RiscV64SysVModel):
    pass


class RiscV64SysVFerror(Ferror, RiscV64SysVModel):
    pass


class RiscV64SysVFgetc(Fgetc, RiscV64SysVModel):
    pass


class RiscV64SysVFgets(Fgets, RiscV64SysVModel):
    pass


class RiscV64SysVFopen(Fopen, RiscV64SysVModel):
    pass


class RiscV64SysVFprintf(Fprintf, RiscV64SysVModel):
    pass


class RiscV64SysVFputc(Fputc, RiscV64SysVModel):
    pass


class RiscV64SysVFputs(Fputs, RiscV64SysVModel):
    pass


class RiscV64SysVFread(Fread, RiscV64SysVModel):
    pass


class RiscV64SysVFscanf(Fscanf, RiscV64SysVModel):
    pass


class RiscV64SysVFseek(Fseek, RiscV64SysVModel):
    pass


class RiscV64SysVFtell(Ftell, RiscV64SysVModel):
    pass


class RiscV64SysVFwrite(Fwrite, RiscV64SysVModel):
    pass


class RiscV64SysVGetc(Getc, RiscV64SysVModel):
    pass


class RiscV64SysVGetchar(Getchar, RiscV64SysVModel):
    pass


class RiscV64SysVPrintf(Printf, RiscV64SysVModel):
    pass


class RiscV64SysVPutc(Putc, RiscV64SysVModel):
    pass


class RiscV64SysVPutchar(Putchar, RiscV64SysVModel):
    pass


class RiscV64SysVPuts(Puts, RiscV64SysVModel):
    pass


class RiscV64SysVRemove(Remove, RiscV64SysVModel):
    pass


class RiscV64SysVRename(Rename, RiscV64SysVModel):
    pass


class RiscV64SysVRewind(Rewind, RiscV64SysVModel):
    pass


class RiscV64SysVScanf(Scanf, RiscV64SysVModel):
    pass


class RiscV64SysVSnprintf(Snprintf, RiscV64SysVModel):
    pass


class RiscV64SysVSprintf(Sprintf, RiscV64SysVModel):
    pass


class RiscV64SysVSscanf(Sscanf, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVFclose",
    "RiscV64SysVFeof",
    "RiscV64SysVFerror",
    "RiscV64SysVFgetc",
    "RiscV64SysVFgets",
    "RiscV64SysVFopen",
    "RiscV64SysVFprintf",
    "RiscV64SysVFputc",
    "RiscV64SysVFputs",
    "RiscV64SysVFread",
    "RiscV64SysVFscanf",
    "RiscV64SysVFseek",
    "RiscV64SysVFtell",
    "RiscV64SysVFwrite",
    "RiscV64SysVGetc",
    "RiscV64SysVGetchar",
    "RiscV64SysVPrintf",
    "RiscV64SysVPutc",
    "RiscV64SysVPutchar",
    "RiscV64SysVPuts",
    "RiscV64SysVRemove",
    "RiscV64SysVRename",
    "RiscV64SysVRewind",
    "RiscV64SysVScanf",
    "RiscV64SysVSnprintf",
    "RiscV64SysVSprintf",
    "RiscV64SysVSscanf",
]
