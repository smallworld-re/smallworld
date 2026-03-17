from ....posix.unistd import (
    Access,
    Alarm,
    Brk,
    Chdir,
    Chown,
    Chroot,
    Close,
    Confstr,
    Crypt,
    Ctermid,
    Cuserid,
    Dup,
    Dup2,
    Encrypt,
    Execl,
    Execle,
    Execlp,
    Execv,
    Execve,
    Execvp,
    Fchdir,
    Fchown,
    Fdatasync,
    Fork,
    Fpathconf,
    Fsync,
    Ftruncate,
    Getcwd,
    Getegid,
    Geteuid,
    Getgid,
    Getgroups,
    Gethostid,
    Getlogin,
    GetloginR,
    Getopt,
    Getpgid,
    Getpgrp,
    Getpid,
    Getppid,
    Getsid,
    Getuid,
    Getwd,
    Isatty,
    Lchown,
    Link,
    Lockf,
    Lseek,
    Nice,
    Pathconf,
    Pause,
    Pipe,
    Pread,
    PthreadAtfork,
    Pwrite,
    Read,
    Readlink,
    Rmdir,
    Sbrk,
    Setegid,
    Seteuid,
    Setgid,
    Setpgid,
    Setpgrp,
    Setregid,
    Setreuid,
    Setsid,
    Sleep,
    Swab,
    Symlink,
    Sync,
    Sysconf,
    Tcgetpgrp,
    TCsetpgrp,
    Truncate,
    Ttyname,
    TtynameR,
    Ularm,
    Unlink,
    Usleep,
    Vfork,
    Write,
)
from ..systemv import MIPSSysVModel


class MIPSSysVAccess(Access, MIPSSysVModel):
    pass


class MIPSSysVAlarm(Alarm, MIPSSysVModel):
    pass


class MIPSSysVBrk(Brk, MIPSSysVModel):
    pass


class MIPSSysVChdir(Chdir, MIPSSysVModel):
    pass


class MIPSSysVChroot(Chroot, MIPSSysVModel):
    pass


class MIPSSysVChown(Chown, MIPSSysVModel):
    pass


class MIPSSysVClose(Close, MIPSSysVModel):
    pass


class MIPSSysVConfstr(Confstr, MIPSSysVModel):
    pass


class MIPSSysVCrypt(Crypt, MIPSSysVModel):
    pass


class MIPSSysVCtermid(Ctermid, MIPSSysVModel):
    pass


class MIPSSysVCuserid(Cuserid, MIPSSysVModel):
    pass


class MIPSSysVDup(Dup, MIPSSysVModel):
    pass


class MIPSSysVDup2(Dup2, MIPSSysVModel):
    pass


class MIPSSysVEncrypt(Encrypt, MIPSSysVModel):
    pass


class MIPSSysVExecl(Execl, MIPSSysVModel):
    pass


class MIPSSysVExecle(Execle, MIPSSysVModel):
    pass


class MIPSSysVExeclp(Execlp, MIPSSysVModel):
    pass


class MIPSSysVExecv(Execv, MIPSSysVModel):
    pass


class MIPSSysVExecvp(Execvp, MIPSSysVModel):
    pass


class MIPSSysVExecve(Execve, MIPSSysVModel):
    pass


class MIPSSysVFchown(Fchown, MIPSSysVModel):
    pass


class MIPSSysVFchdir(Fchdir, MIPSSysVModel):
    pass


class MIPSSysVFdatasync(Fdatasync, MIPSSysVModel):
    pass


class MIPSSysVFork(Fork, MIPSSysVModel):
    pass


class MIPSSysVFpathconf(Fpathconf, MIPSSysVModel):
    pass


class MIPSSysVFsync(Fsync, MIPSSysVModel):
    pass


class MIPSSysVFtruncate(Ftruncate, MIPSSysVModel):
    pass


class MIPSSysVGetcwd(Getcwd, MIPSSysVModel):
    pass


class MIPSSysVGetegid(Getegid, MIPSSysVModel):
    pass


class MIPSSysVGeteuid(Geteuid, MIPSSysVModel):
    pass


class MIPSSysVGetgid(Getgid, MIPSSysVModel):
    pass


class MIPSSysVGetgroups(Getgroups, MIPSSysVModel):
    pass


class MIPSSysVGethostid(Gethostid, MIPSSysVModel):
    pass


class MIPSSysVGetlogin(Getlogin, MIPSSysVModel):
    pass


class MIPSSysVGetloginR(GetloginR, MIPSSysVModel):
    pass


class MIPSSysVGetopt(Getopt, MIPSSysVModel):
    pass


class MIPSSysVGetpgid(Getpgid, MIPSSysVModel):
    pass


class MIPSSysVGetpgrp(Getpgrp, MIPSSysVModel):
    pass


class MIPSSysVGetpid(Getpid, MIPSSysVModel):
    pass


class MIPSSysVGetppid(Getppid, MIPSSysVModel):
    pass


class MIPSSysVGetsid(Getsid, MIPSSysVModel):
    pass


class MIPSSysVGetuid(Getuid, MIPSSysVModel):
    pass


class MIPSSysVGetwd(Getwd, MIPSSysVModel):
    pass


class MIPSSysVIsatty(Isatty, MIPSSysVModel):
    pass


class MIPSSysVLchown(Lchown, MIPSSysVModel):
    pass


class MIPSSysVLink(Link, MIPSSysVModel):
    pass


class MIPSSysVLockf(Lockf, MIPSSysVModel):
    pass


class MIPSSysVLseek(Lseek, MIPSSysVModel):
    pass


class MIPSSysVNice(Nice, MIPSSysVModel):
    pass


class MIPSSysVPathconf(Pathconf, MIPSSysVModel):
    pass


class MIPSSysVPause(Pause, MIPSSysVModel):
    pass


class MIPSSysVPipe(Pipe, MIPSSysVModel):
    pass


class MIPSSysVPread(Pread, MIPSSysVModel):
    pass


class MIPSSysVPthreadAtfork(PthreadAtfork, MIPSSysVModel):
    pass


class MIPSSysVPwrite(Pwrite, MIPSSysVModel):
    pass


class MIPSSysVRead(Read, MIPSSysVModel):
    pass


class MIPSSysVReadlink(Readlink, MIPSSysVModel):
    pass


class MIPSSysVRmdir(Rmdir, MIPSSysVModel):
    pass


class MIPSSysVSbrk(Sbrk, MIPSSysVModel):
    pass


class MIPSSysVSetegid(Setegid, MIPSSysVModel):
    pass


class MIPSSysVSeteuid(Seteuid, MIPSSysVModel):
    pass


class MIPSSysVSetgid(Setgid, MIPSSysVModel):
    pass


class MIPSSysVSetpgid(Setpgid, MIPSSysVModel):
    pass


class MIPSSysVSetpgrp(Setpgrp, MIPSSysVModel):
    pass


class MIPSSysVSetregid(Setregid, MIPSSysVModel):
    pass


class MIPSSysVSetreuid(Setreuid, MIPSSysVModel):
    pass


class MIPSSysVSetsid(Setsid, MIPSSysVModel):
    pass


class MIPSSysVSleep(Sleep, MIPSSysVModel):
    pass


class MIPSSysVSwab(Swab, MIPSSysVModel):
    pass


class MIPSSysVSymlink(Symlink, MIPSSysVModel):
    pass


class MIPSSysVSync(Sync, MIPSSysVModel):
    pass


class MIPSSysVSysconf(Sysconf, MIPSSysVModel):
    pass


class MIPSSysVTcgetpgrp(Tcgetpgrp, MIPSSysVModel):
    pass


class MIPSSysVTCsetpgrp(TCsetpgrp, MIPSSysVModel):
    pass


class MIPSSysVTruncate(Truncate, MIPSSysVModel):
    pass


class MIPSSysVTtyname(Ttyname, MIPSSysVModel):
    pass


class MIPSSysVTtynameR(TtynameR, MIPSSysVModel):
    pass


class MIPSSysVUlarm(Ularm, MIPSSysVModel):
    pass


class MIPSSysVUnlink(Unlink, MIPSSysVModel):
    pass


class MIPSSysVUsleep(Usleep, MIPSSysVModel):
    pass


class MIPSSysVVfork(Vfork, MIPSSysVModel):
    pass


class MIPSSysVWrite(Write, MIPSSysVModel):
    pass


__all__ = [
    "MIPSSysVAccess",
    "MIPSSysVAlarm",
    "MIPSSysVBrk",
    "MIPSSysVChdir",
    "MIPSSysVChroot",
    "MIPSSysVChown",
    "MIPSSysVClose",
    "MIPSSysVConfstr",
    "MIPSSysVCrypt",
    "MIPSSysVCtermid",
    "MIPSSysVCuserid",
    "MIPSSysVDup",
    "MIPSSysVDup2",
    "MIPSSysVEncrypt",
    "MIPSSysVExecl",
    "MIPSSysVExecle",
    "MIPSSysVExeclp",
    "MIPSSysVExecv",
    "MIPSSysVExecvp",
    "MIPSSysVExecve",
    "MIPSSysVFchown",
    "MIPSSysVFchdir",
    "MIPSSysVFdatasync",
    "MIPSSysVFork",
    "MIPSSysVFpathconf",
    "MIPSSysVFsync",
    "MIPSSysVFtruncate",
    "MIPSSysVGetcwd",
    "MIPSSysVGetegid",
    "MIPSSysVGeteuid",
    "MIPSSysVGetgid",
    "MIPSSysVGetgroups",
    "MIPSSysVGethostid",
    "MIPSSysVGetlogin",
    "MIPSSysVGetloginR",
    "MIPSSysVGetopt",
    "MIPSSysVGetpgid",
    "MIPSSysVGetpgrp",
    "MIPSSysVGetpid",
    "MIPSSysVGetppid",
    "MIPSSysVGetsid",
    "MIPSSysVGetuid",
    "MIPSSysVGetwd",
    "MIPSSysVIsatty",
    "MIPSSysVLchown",
    "MIPSSysVLink",
    "MIPSSysVLockf",
    "MIPSSysVLseek",
    "MIPSSysVNice",
    "MIPSSysVPathconf",
    "MIPSSysVPause",
    "MIPSSysVPipe",
    "MIPSSysVPread",
    "MIPSSysVPthreadAtfork",
    "MIPSSysVPwrite",
    "MIPSSysVRead",
    "MIPSSysVReadlink",
    "MIPSSysVRmdir",
    "MIPSSysVSbrk",
    "MIPSSysVSetegid",
    "MIPSSysVSeteuid",
    "MIPSSysVSetgid",
    "MIPSSysVSetpgid",
    "MIPSSysVSetpgrp",
    "MIPSSysVSetregid",
    "MIPSSysVSetreuid",
    "MIPSSysVSetsid",
    "MIPSSysVSleep",
    "MIPSSysVSwab",
    "MIPSSysVSymlink",
    "MIPSSysVSync",
    "MIPSSysVSysconf",
    "MIPSSysVTcgetpgrp",
    "MIPSSysVTCsetpgrp",
    "MIPSSysVTruncate",
    "MIPSSysVTtyname",
    "MIPSSysVTtynameR",
    "MIPSSysVUlarm",
    "MIPSSysVUnlink",
    "MIPSSysVUsleep",
    "MIPSSysVVfork",
    "MIPSSysVWrite",
]
