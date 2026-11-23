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
from ..systemv import MicroMIPSSysVModel


class MicroMIPSSysVPerror(Perror, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVPrintfChk(PrintfChk, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFprintfChk(FprintfChk, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSnprintfChk(SnprintfChk, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSprintfChk(SprintfChk, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFclose(Fclose, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFeof(Feof, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFerror(Ferror, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFgetc(Fgetc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFgets(Fgets, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFopen(Fopen, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFprintf(Fprintf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFputc(Fputc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFputs(Fputs, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFread(Fread, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFscanf(Fscanf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFseek(Fseek, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFtell(Ftell, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFwrite(Fwrite, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVGetc(Getc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVGetchar(Getchar, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVGets(Gets, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVPrintf(Printf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVPutc(Putc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVPutchar(Putchar, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVPuts(Puts, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVRemove(Remove, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVRename(Rename, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVRewind(Rewind, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVScanf(Scanf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSnprintf(Snprintf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSprintf(Sprintf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVSscanf(Sscanf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVClearerr(Clearerr, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFflush(Fflush, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFreopen(Freopen, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFgetpos(Fgetpos, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVFsetpos(Fsetpos, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVTmpfile(Tmpfile, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVTmpnam(Tmpnam, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVUngetc(Ungetc, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVVfprintf(Vfprintf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVVfscanf(Vfscanf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVVprintf(Vprintf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVVscanf(Vscanf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVVsnprintf(Vsnprintf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVVsprintf(Vsprintf, MicroMIPSSysVModel):
    pass


class MicroMIPSSysVVsscanf(Vsscanf, MicroMIPSSysVModel):
    pass


__all__ = [
    "MicroMIPSSysVPerror",
    "MicroMIPSSysVPrintfChk",
    "MicroMIPSSysVFprintfChk",
    "MicroMIPSSysVSnprintfChk",
    "MicroMIPSSysVSprintfChk",
    "MicroMIPSSysVFclose",
    "MicroMIPSSysVFeof",
    "MicroMIPSSysVFerror",
    "MicroMIPSSysVFgetc",
    "MicroMIPSSysVFgets",
    "MicroMIPSSysVFopen",
    "MicroMIPSSysVFprintf",
    "MicroMIPSSysVFputc",
    "MicroMIPSSysVFputs",
    "MicroMIPSSysVFread",
    "MicroMIPSSysVFscanf",
    "MicroMIPSSysVFseek",
    "MicroMIPSSysVFtell",
    "MicroMIPSSysVFwrite",
    "MicroMIPSSysVGetc",
    "MicroMIPSSysVGetchar",
    "MicroMIPSSysVGets",
    "MicroMIPSSysVPrintf",
    "MicroMIPSSysVPutc",
    "MicroMIPSSysVPutchar",
    "MicroMIPSSysVPuts",
    "MicroMIPSSysVRemove",
    "MicroMIPSSysVRename",
    "MicroMIPSSysVRewind",
    "MicroMIPSSysVScanf",
    "MicroMIPSSysVSnprintf",
    "MicroMIPSSysVSprintf",
    "MicroMIPSSysVSscanf",
    "MicroMIPSSysVClearerr",
    "MicroMIPSSysVFflush",
    "MicroMIPSSysVFreopen",
    "MicroMIPSSysVFgetpos",
    "MicroMIPSSysVFsetpos",
    "MicroMIPSSysVTmpfile",
    "MicroMIPSSysVTmpnam",
    "MicroMIPSSysVUngetc",
    "MicroMIPSSysVVfprintf",
    "MicroMIPSSysVVfscanf",
    "MicroMIPSSysVVprintf",
    "MicroMIPSSysVVscanf",
    "MicroMIPSSysVVsnprintf",
    "MicroMIPSSysVVsprintf",
    "MicroMIPSSysVVsscanf",
]
