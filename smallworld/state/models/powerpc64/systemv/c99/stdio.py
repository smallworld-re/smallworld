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
from ..systemv import PowerPC64SysVModel


class PowerPC64SysVPerror(Perror, PowerPC64SysVModel):
    pass


class PowerPC64SysVPrintfChk(PrintfChk, PowerPC64SysVModel):
    pass


class PowerPC64SysVFprintfChk(FprintfChk, PowerPC64SysVModel):
    pass


class PowerPC64SysVSnprintfChk(SnprintfChk, PowerPC64SysVModel):
    pass


class PowerPC64SysVSprintfChk(SprintfChk, PowerPC64SysVModel):
    pass


class PowerPC64SysVFclose(Fclose, PowerPC64SysVModel):
    pass


class PowerPC64SysVFeof(Feof, PowerPC64SysVModel):
    pass


class PowerPC64SysVFerror(Ferror, PowerPC64SysVModel):
    pass


class PowerPC64SysVFgetc(Fgetc, PowerPC64SysVModel):
    pass


class PowerPC64SysVFgets(Fgets, PowerPC64SysVModel):
    pass


class PowerPC64SysVFopen(Fopen, PowerPC64SysVModel):
    pass


class PowerPC64SysVFprintf(Fprintf, PowerPC64SysVModel):
    pass


class PowerPC64SysVFputc(Fputc, PowerPC64SysVModel):
    pass


class PowerPC64SysVFputs(Fputs, PowerPC64SysVModel):
    pass


class PowerPC64SysVFread(Fread, PowerPC64SysVModel):
    pass


class PowerPC64SysVFscanf(Fscanf, PowerPC64SysVModel):
    pass


class PowerPC64SysVFseek(Fseek, PowerPC64SysVModel):
    pass


class PowerPC64SysVFtell(Ftell, PowerPC64SysVModel):
    pass


class PowerPC64SysVFwrite(Fwrite, PowerPC64SysVModel):
    pass


class PowerPC64SysVGetc(Getc, PowerPC64SysVModel):
    pass


class PowerPC64SysVGetchar(Getchar, PowerPC64SysVModel):
    pass


class PowerPC64SysVGets(Gets, PowerPC64SysVModel):
    pass


class PowerPC64SysVPrintf(Printf, PowerPC64SysVModel):
    pass


class PowerPC64SysVPutc(Putc, PowerPC64SysVModel):
    pass


class PowerPC64SysVPutchar(Putchar, PowerPC64SysVModel):
    pass


class PowerPC64SysVPuts(Puts, PowerPC64SysVModel):
    pass


class PowerPC64SysVRemove(Remove, PowerPC64SysVModel):
    pass


class PowerPC64SysVRename(Rename, PowerPC64SysVModel):
    pass


class PowerPC64SysVRewind(Rewind, PowerPC64SysVModel):
    pass


class PowerPC64SysVScanf(Scanf, PowerPC64SysVModel):
    pass


class PowerPC64SysVSnprintf(Snprintf, PowerPC64SysVModel):
    pass


class PowerPC64SysVSprintf(Sprintf, PowerPC64SysVModel):
    pass


class PowerPC64SysVSscanf(Sscanf, PowerPC64SysVModel):
    pass


class PowerPC64SysVClearerr(Clearerr, PowerPC64SysVModel):
    pass


class PowerPC64SysVFflush(Fflush, PowerPC64SysVModel):
    pass


class PowerPC64SysVFreopen(Freopen, PowerPC64SysVModel):
    pass


class PowerPC64SysVFgetpos(Fgetpos, PowerPC64SysVModel):
    pass


class PowerPC64SysVFsetpos(Fsetpos, PowerPC64SysVModel):
    pass


class PowerPC64SysVTmpfile(Tmpfile, PowerPC64SysVModel):
    pass


class PowerPC64SysVTmpnam(Tmpnam, PowerPC64SysVModel):
    pass


class PowerPC64SysVUngetc(Ungetc, PowerPC64SysVModel):
    pass


class PowerPC64SysVVfprintf(Vfprintf, PowerPC64SysVModel):
    pass


class PowerPC64SysVVfscanf(Vfscanf, PowerPC64SysVModel):
    pass


class PowerPC64SysVVprintf(Vprintf, PowerPC64SysVModel):
    pass


class PowerPC64SysVVscanf(Vscanf, PowerPC64SysVModel):
    pass


class PowerPC64SysVVsnprintf(Vsnprintf, PowerPC64SysVModel):
    pass


class PowerPC64SysVVsprintf(Vsprintf, PowerPC64SysVModel):
    pass


class PowerPC64SysVVsscanf(Vsscanf, PowerPC64SysVModel):
    pass


__all__ = [
    "PowerPC64SysVPerror",
    "PowerPC64SysVPrintfChk",
    "PowerPC64SysVFprintfChk",
    "PowerPC64SysVSnprintfChk",
    "PowerPC64SysVSprintfChk",
    "PowerPC64SysVFclose",
    "PowerPC64SysVFeof",
    "PowerPC64SysVFerror",
    "PowerPC64SysVFgetc",
    "PowerPC64SysVFgets",
    "PowerPC64SysVFopen",
    "PowerPC64SysVFprintf",
    "PowerPC64SysVFputc",
    "PowerPC64SysVFputs",
    "PowerPC64SysVFread",
    "PowerPC64SysVFscanf",
    "PowerPC64SysVFseek",
    "PowerPC64SysVFtell",
    "PowerPC64SysVFwrite",
    "PowerPC64SysVGetc",
    "PowerPC64SysVGetchar",
    "PowerPC64SysVGets",
    "PowerPC64SysVPrintf",
    "PowerPC64SysVPutc",
    "PowerPC64SysVPutchar",
    "PowerPC64SysVPuts",
    "PowerPC64SysVRemove",
    "PowerPC64SysVRename",
    "PowerPC64SysVRewind",
    "PowerPC64SysVScanf",
    "PowerPC64SysVSnprintf",
    "PowerPC64SysVSprintf",
    "PowerPC64SysVSscanf",
    "PowerPC64SysVClearerr",
    "PowerPC64SysVFflush",
    "PowerPC64SysVFreopen",
    "PowerPC64SysVFgetpos",
    "PowerPC64SysVFsetpos",
    "PowerPC64SysVTmpfile",
    "PowerPC64SysVTmpnam",
    "PowerPC64SysVUngetc",
    "PowerPC64SysVVfprintf",
    "PowerPC64SysVVfscanf",
    "PowerPC64SysVVprintf",
    "PowerPC64SysVVscanf",
    "PowerPC64SysVVsnprintf",
    "PowerPC64SysVVsprintf",
    "PowerPC64SysVVsscanf",
]
