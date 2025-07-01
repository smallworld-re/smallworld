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
from ..systemv import MIPSELSysVModel


class MIPSELSysVFclose(Fclose, MIPSELSysVModel):
    pass


class MIPSELSysVFeof(Feof, MIPSELSysVModel):
    pass


class MIPSELSysVFerror(Ferror, MIPSELSysVModel):
    pass


class MIPSELSysVFgetc(Fgetc, MIPSELSysVModel):
    pass


class MIPSELSysVFgets(Fgets, MIPSELSysVModel):
    pass


class MIPSELSysVFopen(Fopen, MIPSELSysVModel):
    pass


class MIPSELSysVFprintf(Fprintf, MIPSELSysVModel):
    pass


class MIPSELSysVFputc(Fputc, MIPSELSysVModel):
    pass


class MIPSELSysVFputs(Fputs, MIPSELSysVModel):
    pass


class MIPSELSysVFread(Fread, MIPSELSysVModel):
    pass


class MIPSELSysVFscanf(Fscanf, MIPSELSysVModel):
    pass


class MIPSELSysVFseek(Fseek, MIPSELSysVModel):
    pass


class MIPSELSysVFtell(Ftell, MIPSELSysVModel):
    pass


class MIPSELSysVFwrite(Fwrite, MIPSELSysVModel):
    pass


class MIPSELSysVGetc(Getc, MIPSELSysVModel):
    pass


class MIPSELSysVGetchar(Getchar, MIPSELSysVModel):
    pass


class MIPSELSysVPrintf(Printf, MIPSELSysVModel):
    pass


class MIPSELSysVPutc(Putc, MIPSELSysVModel):
    pass


class MIPSELSysVPutchar(Putchar, MIPSELSysVModel):
    pass


class MIPSELSysVPuts(Puts, MIPSELSysVModel):
    pass


class MIPSELSysVRemove(Remove, MIPSELSysVModel):
    pass


class MIPSELSysVRename(Rename, MIPSELSysVModel):
    pass


class MIPSELSysVRewind(Rewind, MIPSELSysVModel):
    pass


class MIPSELSysVScanf(Scanf, MIPSELSysVModel):
    pass


class MIPSELSysVSnprintf(Snprintf, MIPSELSysVModel):
    pass


class MIPSELSysVSprintf(Sprintf, MIPSELSysVModel):
    pass


class MIPSELSysVSscanf(Sscanf, MIPSELSysVModel):
    pass


__all__ = [
    "MIPSELSysVFclose",
    "MIPSELSysVFeof",
    "MIPSELSysVFerror",
    "MIPSELSysVFgetc",
    "MIPSELSysVFgets",
    "MIPSELSysVFopen",
    "MIPSELSysVFprintf",
    "MIPSELSysVFputc",
    "MIPSELSysVFputs",
    "MIPSELSysVFread",
    "MIPSELSysVFscanf",
    "MIPSELSysVFseek",
    "MIPSELSysVFtell",
    "MIPSELSysVFwrite",
    "MIPSELSysVGetc",
    "MIPSELSysVGetchar",
    "MIPSELSysVPrintf",
    "MIPSELSysVPutc",
    "MIPSELSysVPutchar",
    "MIPSELSysVPuts",
    "MIPSELSysVRemove",
    "MIPSELSysVRename",
    "MIPSELSysVRewind",
    "MIPSELSysVScanf",
    "MIPSELSysVSnprintf",
    "MIPSELSysVSprintf",
    "MIPSELSysVSscanf",
]
