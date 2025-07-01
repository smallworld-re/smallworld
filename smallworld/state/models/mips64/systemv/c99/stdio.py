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
from ..systemv import MIPS64SysVModel


class MIPS64SysVFclose(Fclose, MIPS64SysVModel):
    pass


class MIPS64SysVFeof(Feof, MIPS64SysVModel):
    pass


class MIPS64SysVFerror(Ferror, MIPS64SysVModel):
    pass


class MIPS64SysVFgetc(Fgetc, MIPS64SysVModel):
    pass


class MIPS64SysVFgets(Fgets, MIPS64SysVModel):
    pass


class MIPS64SysVFopen(Fopen, MIPS64SysVModel):
    pass


class MIPS64SysVFprintf(Fprintf, MIPS64SysVModel):
    pass


class MIPS64SysVFputc(Fputc, MIPS64SysVModel):
    pass


class MIPS64SysVFputs(Fputs, MIPS64SysVModel):
    pass


class MIPS64SysVFread(Fread, MIPS64SysVModel):
    pass


class MIPS64SysVFscanf(Fscanf, MIPS64SysVModel):
    pass


class MIPS64SysVFseek(Fseek, MIPS64SysVModel):
    pass


class MIPS64SysVFtell(Ftell, MIPS64SysVModel):
    pass


class MIPS64SysVFwrite(Fwrite, MIPS64SysVModel):
    pass


class MIPS64SysVGetc(Getc, MIPS64SysVModel):
    pass


class MIPS64SysVGetchar(Getchar, MIPS64SysVModel):
    pass


class MIPS64SysVPrintf(Printf, MIPS64SysVModel):
    pass


class MIPS64SysVPutc(Putc, MIPS64SysVModel):
    pass


class MIPS64SysVPutchar(Putchar, MIPS64SysVModel):
    pass


class MIPS64SysVPuts(Puts, MIPS64SysVModel):
    pass


class MIPS64SysVRemove(Remove, MIPS64SysVModel):
    pass


class MIPS64SysVRename(Rename, MIPS64SysVModel):
    pass


class MIPS64SysVRewind(Rewind, MIPS64SysVModel):
    pass


class MIPS64SysVScanf(Scanf, MIPS64SysVModel):
    pass


class MIPS64SysVSnprintf(Snprintf, MIPS64SysVModel):
    pass


class MIPS64SysVSprintf(Sprintf, MIPS64SysVModel):
    pass


class MIPS64SysVSscanf(Sscanf, MIPS64SysVModel):
    pass


__all__ = [
    "MIPS64SysVFclose",
    "MIPS64SysVFeof",
    "MIPS64SysVFerror",
    "MIPS64SysVFgetc",
    "MIPS64SysVFgets",
    "MIPS64SysVFopen",
    "MIPS64SysVFprintf",
    "MIPS64SysVFputc",
    "MIPS64SysVFputs",
    "MIPS64SysVFread",
    "MIPS64SysVFscanf",
    "MIPS64SysVFseek",
    "MIPS64SysVFtell",
    "MIPS64SysVFwrite",
    "MIPS64SysVGetc",
    "MIPS64SysVGetchar",
    "MIPS64SysVPrintf",
    "MIPS64SysVPutc",
    "MIPS64SysVPutchar",
    "MIPS64SysVPuts",
    "MIPS64SysVRemove",
    "MIPS64SysVRename",
    "MIPS64SysVRewind",
    "MIPS64SysVScanf",
    "MIPS64SysVSnprintf",
    "MIPS64SysVSprintf",
    "MIPS64SysVSscanf",
]
