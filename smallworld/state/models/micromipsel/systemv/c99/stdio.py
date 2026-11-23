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
    FprintfChk,
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
    Gets,
    Perror,
    Printf,
    PrintfChk,
    Putc,
    Putchar,
    Puts,
    Remove,
    Rename,
    Rewind,
    Scanf,
    Snprintf,
    SnprintfChk,
    Sprintf,
    SprintfChk,
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
from ..systemv import MicroMIPSELSysVModel


class MicroMIPSELSysVPerror(Perror, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVPrintfChk(PrintfChk, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFprintfChk(FprintfChk, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSnprintfChk(SnprintfChk, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSprintfChk(SprintfChk, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFclose(Fclose, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFeof(Feof, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFerror(Ferror, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFgetc(Fgetc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFgets(Fgets, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFopen(Fopen, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFprintf(Fprintf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFputc(Fputc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFputs(Fputs, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFread(Fread, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFscanf(Fscanf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFseek(Fseek, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFtell(Ftell, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFwrite(Fwrite, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVGetc(Getc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVGetchar(Getchar, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVGets(Gets, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVPrintf(Printf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVPutc(Putc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVPutchar(Putchar, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVPuts(Puts, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVRemove(Remove, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVRename(Rename, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVRewind(Rewind, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVScanf(Scanf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSnprintf(Snprintf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSprintf(Sprintf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVSscanf(Sscanf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVClearerr(Clearerr, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFflush(Fflush, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFreopen(Freopen, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFgetpos(Fgetpos, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVFsetpos(Fsetpos, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVTmpfile(Tmpfile, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVTmpnam(Tmpnam, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVUngetc(Ungetc, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVVfprintf(Vfprintf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVVfscanf(Vfscanf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVVprintf(Vprintf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVVscanf(Vscanf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVVsnprintf(Vsnprintf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVVsprintf(Vsprintf, MicroMIPSELSysVModel):
    pass


class MicroMIPSELSysVVsscanf(Vsscanf, MicroMIPSELSysVModel):
    pass


__all__ = [
    "MicroMIPSELSysVPerror",
    "MicroMIPSELSysVPrintfChk",
    "MicroMIPSELSysVFprintfChk",
    "MicroMIPSELSysVSnprintfChk",
    "MicroMIPSELSysVSprintfChk",
    "MicroMIPSELSysVFclose",
    "MicroMIPSELSysVFeof",
    "MicroMIPSELSysVFerror",
    "MicroMIPSELSysVFgetc",
    "MicroMIPSELSysVFgets",
    "MicroMIPSELSysVFopen",
    "MicroMIPSELSysVFprintf",
    "MicroMIPSELSysVFputc",
    "MicroMIPSELSysVFputs",
    "MicroMIPSELSysVFread",
    "MicroMIPSELSysVFscanf",
    "MicroMIPSELSysVFseek",
    "MicroMIPSELSysVFtell",
    "MicroMIPSELSysVFwrite",
    "MicroMIPSELSysVGetc",
    "MicroMIPSELSysVGetchar",
    "MicroMIPSELSysVGets",
    "MicroMIPSELSysVPrintf",
    "MicroMIPSELSysVPutc",
    "MicroMIPSELSysVPutchar",
    "MicroMIPSELSysVPuts",
    "MicroMIPSELSysVRemove",
    "MicroMIPSELSysVRename",
    "MicroMIPSELSysVRewind",
    "MicroMIPSELSysVScanf",
    "MicroMIPSELSysVSnprintf",
    "MicroMIPSELSysVSprintf",
    "MicroMIPSELSysVSscanf",
    "MicroMIPSELSysVClearerr",
    "MicroMIPSELSysVFflush",
    "MicroMIPSELSysVFreopen",
    "MicroMIPSELSysVFgetpos",
    "MicroMIPSELSysVFsetpos",
    "MicroMIPSELSysVTmpfile",
    "MicroMIPSELSysVTmpnam",
    "MicroMIPSELSysVUngetc",
    "MicroMIPSELSysVVfprintf",
    "MicroMIPSELSysVVfscanf",
    "MicroMIPSELSysVVprintf",
    "MicroMIPSELSysVVscanf",
    "MicroMIPSELSysVVsnprintf",
    "MicroMIPSELSysVVsprintf",
    "MicroMIPSELSysVVsscanf",
]
