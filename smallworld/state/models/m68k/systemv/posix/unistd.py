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
from ..systemv import M68KSysVModel


class M68KSysVAccess(Access, M68KSysVModel):
    pass


class M68KSysVAlarm(Alarm, M68KSysVModel):
    pass


class M68KSysVBrk(Brk, M68KSysVModel):
    pass


class M68KSysVChdir(Chdir, M68KSysVModel):
    pass


class M68KSysVChroot(Chroot, M68KSysVModel):
    pass


class M68KSysVChown(Chown, M68KSysVModel):
    pass


class M68KSysVClose(Close, M68KSysVModel):
    pass


class M68KSysVConfstr(Confstr, M68KSysVModel):
    pass


class M68KSysVCrypt(Crypt, M68KSysVModel):
    pass


class M68KSysVCtermid(Ctermid, M68KSysVModel):
    pass


class M68KSysVCuserid(Cuserid, M68KSysVModel):
    pass


class M68KSysVDup(Dup, M68KSysVModel):
    pass


class M68KSysVDup2(Dup2, M68KSysVModel):
    pass


class M68KSysVEncrypt(Encrypt, M68KSysVModel):
    pass


class M68KSysVExecl(Execl, M68KSysVModel):
    pass


class M68KSysVExecle(Execle, M68KSysVModel):
    pass


class M68KSysVExeclp(Execlp, M68KSysVModel):
    pass


class M68KSysVExecv(Execv, M68KSysVModel):
    pass


class M68KSysVExecvp(Execvp, M68KSysVModel):
    pass


class M68KSysVExecve(Execve, M68KSysVModel):
    pass


class M68KSysVFchown(Fchown, M68KSysVModel):
    pass


class M68KSysVFchdir(Fchdir, M68KSysVModel):
    pass


class M68KSysVFdatasync(Fdatasync, M68KSysVModel):
    pass


class M68KSysVFork(Fork, M68KSysVModel):
    pass


class M68KSysVFpathconf(Fpathconf, M68KSysVModel):
    pass


class M68KSysVFsync(Fsync, M68KSysVModel):
    pass


class M68KSysVFtruncate(Ftruncate, M68KSysVModel):
    pass


class M68KSysVGetcwd(Getcwd, M68KSysVModel):
    pass


class M68KSysVGetegid(Getegid, M68KSysVModel):
    pass


class M68KSysVGeteuid(Geteuid, M68KSysVModel):
    pass


class M68KSysVGetgid(Getgid, M68KSysVModel):
    pass


class M68KSysVGetgroups(Getgroups, M68KSysVModel):
    pass


class M68KSysVGethostid(Gethostid, M68KSysVModel):
    pass


class M68KSysVGetlogin(Getlogin, M68KSysVModel):
    pass


class M68KSysVGetloginR(GetloginR, M68KSysVModel):
    pass


class M68KSysVGetopt(Getopt, M68KSysVModel):
    pass


class M68KSysVGetpgid(Getpgid, M68KSysVModel):
    pass


class M68KSysVGetpgrp(Getpgrp, M68KSysVModel):
    pass


class M68KSysVGetpid(Getpid, M68KSysVModel):
    pass


class M68KSysVGetppid(Getppid, M68KSysVModel):
    pass


class M68KSysVGetsid(Getsid, M68KSysVModel):
    pass


class M68KSysVGetuid(Getuid, M68KSysVModel):
    pass


class M68KSysVGetwd(Getwd, M68KSysVModel):
    pass


class M68KSysVIsatty(Isatty, M68KSysVModel):
    pass


class M68KSysVLchown(Lchown, M68KSysVModel):
    pass


class M68KSysVLink(Link, M68KSysVModel):
    pass


class M68KSysVLockf(Lockf, M68KSysVModel):
    pass


class M68KSysVLseek(Lseek, M68KSysVModel):
    pass


class M68KSysVNice(Nice, M68KSysVModel):
    pass


class M68KSysVPathconf(Pathconf, M68KSysVModel):
    pass


class M68KSysVPause(Pause, M68KSysVModel):
    pass


class M68KSysVPipe(Pipe, M68KSysVModel):
    pass


class M68KSysVPread(Pread, M68KSysVModel):
    pass


class M68KSysVPthreadAtfork(PthreadAtfork, M68KSysVModel):
    pass


class M68KSysVPwrite(Pwrite, M68KSysVModel):
    pass


class M68KSysVRead(Read, M68KSysVModel):
    pass


class M68KSysVReadlink(Readlink, M68KSysVModel):
    pass


class M68KSysVRmdir(Rmdir, M68KSysVModel):
    pass


class M68KSysVSbrk(Sbrk, M68KSysVModel):
    pass


class M68KSysVSetegid(Setegid, M68KSysVModel):
    pass


class M68KSysVSeteuid(Seteuid, M68KSysVModel):
    pass


class M68KSysVSetgid(Setgid, M68KSysVModel):
    pass


class M68KSysVSetpgid(Setpgid, M68KSysVModel):
    pass


class M68KSysVSetpgrp(Setpgrp, M68KSysVModel):
    pass


class M68KSysVSetregid(Setregid, M68KSysVModel):
    pass


class M68KSysVSetreuid(Setreuid, M68KSysVModel):
    pass


class M68KSysVSetsid(Setsid, M68KSysVModel):
    pass


class M68KSysVSleep(Sleep, M68KSysVModel):
    pass


class M68KSysVSwab(Swab, M68KSysVModel):
    pass


class M68KSysVSymlink(Symlink, M68KSysVModel):
    pass


class M68KSysVSync(Sync, M68KSysVModel):
    pass


class M68KSysVSysconf(Sysconf, M68KSysVModel):
    pass


class M68KSysVTcgetpgrp(Tcgetpgrp, M68KSysVModel):
    pass


class M68KSysVTCsetpgrp(TCsetpgrp, M68KSysVModel):
    pass


class M68KSysVTruncate(Truncate, M68KSysVModel):
    pass


class M68KSysVTtyname(Ttyname, M68KSysVModel):
    pass


class M68KSysVTtynameR(TtynameR, M68KSysVModel):
    pass


class M68KSysVUlarm(Ularm, M68KSysVModel):
    pass


class M68KSysVUnlink(Unlink, M68KSysVModel):
    pass


class M68KSysVUsleep(Usleep, M68KSysVModel):
    pass


class M68KSysVVfork(Vfork, M68KSysVModel):
    pass


class M68KSysVWrite(Write, M68KSysVModel):
    pass


__all__ = [
    "M68KSysVAccess",
    "M68KSysVAlarm",
    "M68KSysVBrk",
    "M68KSysVChdir",
    "M68KSysVChroot",
    "M68KSysVChown",
    "M68KSysVClose",
    "M68KSysVConfstr",
    "M68KSysVCrypt",
    "M68KSysVCtermid",
    "M68KSysVCuserid",
    "M68KSysVDup",
    "M68KSysVDup2",
    "M68KSysVEncrypt",
    "M68KSysVExecl",
    "M68KSysVExecle",
    "M68KSysVExeclp",
    "M68KSysVExecv",
    "M68KSysVExecvp",
    "M68KSysVExecve",
    "M68KSysVFchown",
    "M68KSysVFchdir",
    "M68KSysVFdatasync",
    "M68KSysVFork",
    "M68KSysVFpathconf",
    "M68KSysVFsync",
    "M68KSysVFtruncate",
    "M68KSysVGetcwd",
    "M68KSysVGetegid",
    "M68KSysVGeteuid",
    "M68KSysVGetgid",
    "M68KSysVGetgroups",
    "M68KSysVGethostid",
    "M68KSysVGetlogin",
    "M68KSysVGetloginR",
    "M68KSysVGetopt",
    "M68KSysVGetpgid",
    "M68KSysVGetpgrp",
    "M68KSysVGetpid",
    "M68KSysVGetppid",
    "M68KSysVGetsid",
    "M68KSysVGetuid",
    "M68KSysVGetwd",
    "M68KSysVIsatty",
    "M68KSysVLchown",
    "M68KSysVLink",
    "M68KSysVLockf",
    "M68KSysVLseek",
    "M68KSysVNice",
    "M68KSysVPathconf",
    "M68KSysVPause",
    "M68KSysVPipe",
    "M68KSysVPread",
    "M68KSysVPthreadAtfork",
    "M68KSysVPwrite",
    "M68KSysVRead",
    "M68KSysVReadlink",
    "M68KSysVRmdir",
    "M68KSysVSbrk",
    "M68KSysVSetegid",
    "M68KSysVSeteuid",
    "M68KSysVSetgid",
    "M68KSysVSetpgid",
    "M68KSysVSetpgrp",
    "M68KSysVSetregid",
    "M68KSysVSetreuid",
    "M68KSysVSetsid",
    "M68KSysVSleep",
    "M68KSysVSwab",
    "M68KSysVSymlink",
    "M68KSysVSync",
    "M68KSysVSysconf",
    "M68KSysVTcgetpgrp",
    "M68KSysVTCsetpgrp",
    "M68KSysVTruncate",
    "M68KSysVTtyname",
    "M68KSysVTtynameR",
    "M68KSysVUlarm",
    "M68KSysVUnlink",
    "M68KSysVUsleep",
    "M68KSysVVfork",
    "M68KSysVWrite",
]
