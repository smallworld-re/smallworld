from ....c99 import (
    Clearerr,
    Fclose,
    Feof,
    Ferror,
    Fflush,
    Fgetc,
    Fgetpos,
    Fgets,
    Fopen,
    Fprintf,
    Fputc,
    Fputs,
    Fread,
    Freopen,
    Fscanf,
    Fseek,
    Fsetpos,
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
    Tmpfile,
    Tmpnam,
    Ungetc,
    Vfprintf,
    Vfscanf,
    Vprintf,
    Vscanf,
    Vsnprintf,
    Vsprintf,
    Vsscanf,
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


class MIPSELSysVClearerr(Clearerr, MIPSELSysVModel):
    pass


class MIPSELSysVFflush(Fflush, MIPSELSysVModel):
    pass


class MIPSELSysVFreopen(Freopen, MIPSELSysVModel):
    pass


class MIPSELSysVFgetpos(Fgetpos, MIPSELSysVModel):
    pass


class MIPSELSysVFsetpos(Fsetpos, MIPSELSysVModel):
    pass


class MIPSELSysVTmpfile(Tmpfile, MIPSELSysVModel):
    pass


class MIPSELSysVTmpnam(Tmpnam, MIPSELSysVModel):
    pass


class MIPSELSysVUngetc(Ungetc, MIPSELSysVModel):
    pass


class MIPSELSysVVfprintf(Vfprintf, MIPSELSysVModel):
    pass


class MIPSELSysVVfscanf(Vfscanf, MIPSELSysVModel):
    pass


class MIPSELSysVVprintf(Vprintf, MIPSELSysVModel):
    pass


class MIPSELSysVVscanf(Vscanf, MIPSELSysVModel):
    pass


class MIPSELSysVVsnprintf(Vsnprintf, MIPSELSysVModel):
    pass


class MIPSELSysVVsprintf(Vsprintf, MIPSELSysVModel):
    pass


class MIPSELSysVVsscanf(Vsscanf, MIPSELSysVModel):
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
    "MIPSELSysVClearerr",
    "MIPSELSysVFflush",
    "MIPSELSysVFreopen",
    "MIPSELSysVFgetpos",
    "MIPSELSysVFsetpos",
    "MIPSELSysVTmpfile",
    "MIPSELSysVTmpnam",
    "MIPSELSysVUngetc",
    "MIPSELSysVVfprintf",
    "MIPSELSysVVfscanf",
    "MIPSELSysVVprintf",
    "MIPSELSysVVscanf",
    "MIPSELSysVVsnprintf",
    "MIPSELSysVVsprintf",
    "MIPSELSysVVsscanf",
]
