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
from ..systemv import ArmELSysVModel


class ArmELSysVFclose(Fclose, ArmELSysVModel):
    pass


class ArmELSysVFeof(Feof, ArmELSysVModel):
    pass


class ArmELSysVFerror(Ferror, ArmELSysVModel):
    pass


class ArmELSysVFgetc(Fgetc, ArmELSysVModel):
    pass


class ArmELSysVFgets(Fgets, ArmELSysVModel):
    pass


class ArmELSysVFopen(Fopen, ArmELSysVModel):
    pass


class ArmELSysVFprintf(Fprintf, ArmELSysVModel):
    pass


class ArmELSysVFputc(Fputc, ArmELSysVModel):
    pass


class ArmELSysVFputs(Fputs, ArmELSysVModel):
    pass


class ArmELSysVFread(Fread, ArmELSysVModel):
    pass


class ArmELSysVFscanf(Fscanf, ArmELSysVModel):
    pass


class ArmELSysVFseek(Fseek, ArmELSysVModel):
    pass


class ArmELSysVFtell(Ftell, ArmELSysVModel):
    pass


class ArmELSysVFwrite(Fwrite, ArmELSysVModel):
    pass


class ArmELSysVGetc(Getc, ArmELSysVModel):
    pass


class ArmELSysVGetchar(Getchar, ArmELSysVModel):
    pass


class ArmELSysVPrintf(Printf, ArmELSysVModel):
    pass


class ArmELSysVPutc(Putc, ArmELSysVModel):
    pass


class ArmELSysVPutchar(Putchar, ArmELSysVModel):
    pass


class ArmELSysVPuts(Puts, ArmELSysVModel):
    pass


class ArmELSysVRemove(Remove, ArmELSysVModel):
    pass


class ArmELSysVRename(Rename, ArmELSysVModel):
    pass


class ArmELSysVRewind(Rewind, ArmELSysVModel):
    pass


class ArmELSysVScanf(Scanf, ArmELSysVModel):
    pass


class ArmELSysVSnprintf(Snprintf, ArmELSysVModel):
    pass


class ArmELSysVSprintf(Sprintf, ArmELSysVModel):
    pass


class ArmELSysVSscanf(Sscanf, ArmELSysVModel):
    pass


__all__ = [
    "ArmELSysVFclose",
    "ArmELSysVFeof",
    "ArmELSysVFerror",
    "ArmELSysVFgetc",
    "ArmELSysVFgets",
    "ArmELSysVFopen",
    "ArmELSysVFprintf",
    "ArmELSysVFputc",
    "ArmELSysVFputs",
    "ArmELSysVFread",
    "ArmELSysVFscanf",
    "ArmELSysVFseek",
    "ArmELSysVFtell",
    "ArmELSysVFwrite",
    "ArmELSysVGetc",
    "ArmELSysVGetchar",
    "ArmELSysVPrintf",
    "ArmELSysVPutc",
    "ArmELSysVPutchar",
    "ArmELSysVPuts",
    "ArmELSysVRemove",
    "ArmELSysVRename",
    "ArmELSysVRewind",
    "ArmELSysVScanf",
    "ArmELSysVSnprintf",
    "ArmELSysVSprintf",
    "ArmELSysVSscanf",
]
