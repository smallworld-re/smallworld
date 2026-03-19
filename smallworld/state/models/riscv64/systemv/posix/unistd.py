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
from ..systemv import RiscV64SysVModel


class RiscV64SysVAccess(Access, RiscV64SysVModel):
    pass


class RiscV64SysVAlarm(Alarm, RiscV64SysVModel):
    pass


class RiscV64SysVBrk(Brk, RiscV64SysVModel):
    pass


class RiscV64SysVChdir(Chdir, RiscV64SysVModel):
    pass


class RiscV64SysVChroot(Chroot, RiscV64SysVModel):
    pass


class RiscV64SysVChown(Chown, RiscV64SysVModel):
    pass


class RiscV64SysVClose(Close, RiscV64SysVModel):
    pass


class RiscV64SysVConfstr(Confstr, RiscV64SysVModel):
    pass


class RiscV64SysVCrypt(Crypt, RiscV64SysVModel):
    pass


class RiscV64SysVCtermid(Ctermid, RiscV64SysVModel):
    pass


class RiscV64SysVCuserid(Cuserid, RiscV64SysVModel):
    pass


class RiscV64SysVDup(Dup, RiscV64SysVModel):
    pass


class RiscV64SysVDup2(Dup2, RiscV64SysVModel):
    pass


class RiscV64SysVEncrypt(Encrypt, RiscV64SysVModel):
    pass


class RiscV64SysVExecl(Execl, RiscV64SysVModel):
    pass


class RiscV64SysVExecle(Execle, RiscV64SysVModel):
    pass


class RiscV64SysVExeclp(Execlp, RiscV64SysVModel):
    pass


class RiscV64SysVExecv(Execv, RiscV64SysVModel):
    pass


class RiscV64SysVExecvp(Execvp, RiscV64SysVModel):
    pass


class RiscV64SysVExecve(Execve, RiscV64SysVModel):
    pass


class RiscV64SysVFchown(Fchown, RiscV64SysVModel):
    pass


class RiscV64SysVFchdir(Fchdir, RiscV64SysVModel):
    pass


class RiscV64SysVFdatasync(Fdatasync, RiscV64SysVModel):
    pass


class RiscV64SysVFork(Fork, RiscV64SysVModel):
    pass


class RiscV64SysVFpathconf(Fpathconf, RiscV64SysVModel):
    pass


class RiscV64SysVFsync(Fsync, RiscV64SysVModel):
    pass


class RiscV64SysVFtruncate(Ftruncate, RiscV64SysVModel):
    pass


class RiscV64SysVGetcwd(Getcwd, RiscV64SysVModel):
    pass


class RiscV64SysVGetegid(Getegid, RiscV64SysVModel):
    pass


class RiscV64SysVGeteuid(Geteuid, RiscV64SysVModel):
    pass


class RiscV64SysVGetgid(Getgid, RiscV64SysVModel):
    pass


class RiscV64SysVGetgroups(Getgroups, RiscV64SysVModel):
    pass


class RiscV64SysVGethostid(Gethostid, RiscV64SysVModel):
    pass


class RiscV64SysVGetlogin(Getlogin, RiscV64SysVModel):
    pass


class RiscV64SysVGetloginR(GetloginR, RiscV64SysVModel):
    pass


class RiscV64SysVGetopt(Getopt, RiscV64SysVModel):
    pass


class RiscV64SysVGetpgid(Getpgid, RiscV64SysVModel):
    pass


class RiscV64SysVGetpgrp(Getpgrp, RiscV64SysVModel):
    pass


class RiscV64SysVGetpid(Getpid, RiscV64SysVModel):
    pass


class RiscV64SysVGetppid(Getppid, RiscV64SysVModel):
    pass


class RiscV64SysVGetsid(Getsid, RiscV64SysVModel):
    pass


class RiscV64SysVGetuid(Getuid, RiscV64SysVModel):
    pass


class RiscV64SysVGetwd(Getwd, RiscV64SysVModel):
    pass


class RiscV64SysVIsatty(Isatty, RiscV64SysVModel):
    pass


class RiscV64SysVLchown(Lchown, RiscV64SysVModel):
    pass


class RiscV64SysVLink(Link, RiscV64SysVModel):
    pass


class RiscV64SysVLockf(Lockf, RiscV64SysVModel):
    pass


class RiscV64SysVLseek(Lseek, RiscV64SysVModel):
    pass


class RiscV64SysVNice(Nice, RiscV64SysVModel):
    pass


class RiscV64SysVPathconf(Pathconf, RiscV64SysVModel):
    pass


class RiscV64SysVPause(Pause, RiscV64SysVModel):
    pass


class RiscV64SysVPipe(Pipe, RiscV64SysVModel):
    pass


class RiscV64SysVPread(Pread, RiscV64SysVModel):
    pass


class RiscV64SysVPthreadAtfork(PthreadAtfork, RiscV64SysVModel):
    pass


class RiscV64SysVPwrite(Pwrite, RiscV64SysVModel):
    pass


class RiscV64SysVRead(Read, RiscV64SysVModel):
    pass


class RiscV64SysVReadlink(Readlink, RiscV64SysVModel):
    pass


class RiscV64SysVRmdir(Rmdir, RiscV64SysVModel):
    pass


class RiscV64SysVSbrk(Sbrk, RiscV64SysVModel):
    pass


class RiscV64SysVSetegid(Setegid, RiscV64SysVModel):
    pass


class RiscV64SysVSeteuid(Seteuid, RiscV64SysVModel):
    pass


class RiscV64SysVSetgid(Setgid, RiscV64SysVModel):
    pass


class RiscV64SysVSetpgid(Setpgid, RiscV64SysVModel):
    pass


class RiscV64SysVSetpgrp(Setpgrp, RiscV64SysVModel):
    pass


class RiscV64SysVSetregid(Setregid, RiscV64SysVModel):
    pass


class RiscV64SysVSetreuid(Setreuid, RiscV64SysVModel):
    pass


class RiscV64SysVSetsid(Setsid, RiscV64SysVModel):
    pass


class RiscV64SysVSleep(Sleep, RiscV64SysVModel):
    pass


class RiscV64SysVSwab(Swab, RiscV64SysVModel):
    pass


class RiscV64SysVSymlink(Symlink, RiscV64SysVModel):
    pass


class RiscV64SysVSync(Sync, RiscV64SysVModel):
    pass


class RiscV64SysVSysconf(Sysconf, RiscV64SysVModel):
    pass


class RiscV64SysVTcgetpgrp(Tcgetpgrp, RiscV64SysVModel):
    pass


class RiscV64SysVTCsetpgrp(TCsetpgrp, RiscV64SysVModel):
    pass


class RiscV64SysVTruncate(Truncate, RiscV64SysVModel):
    pass


class RiscV64SysVTtyname(Ttyname, RiscV64SysVModel):
    pass


class RiscV64SysVTtynameR(TtynameR, RiscV64SysVModel):
    pass


class RiscV64SysVUlarm(Ularm, RiscV64SysVModel):
    pass


class RiscV64SysVUnlink(Unlink, RiscV64SysVModel):
    pass


class RiscV64SysVUsleep(Usleep, RiscV64SysVModel):
    pass


class RiscV64SysVVfork(Vfork, RiscV64SysVModel):
    pass


class RiscV64SysVWrite(Write, RiscV64SysVModel):
    pass


__all__ = [
    "RiscV64SysVAccess",
    "RiscV64SysVAlarm",
    "RiscV64SysVBrk",
    "RiscV64SysVChdir",
    "RiscV64SysVChroot",
    "RiscV64SysVChown",
    "RiscV64SysVClose",
    "RiscV64SysVConfstr",
    "RiscV64SysVCrypt",
    "RiscV64SysVCtermid",
    "RiscV64SysVCuserid",
    "RiscV64SysVDup",
    "RiscV64SysVDup2",
    "RiscV64SysVEncrypt",
    "RiscV64SysVExecl",
    "RiscV64SysVExecle",
    "RiscV64SysVExeclp",
    "RiscV64SysVExecv",
    "RiscV64SysVExecvp",
    "RiscV64SysVExecve",
    "RiscV64SysVFchown",
    "RiscV64SysVFchdir",
    "RiscV64SysVFdatasync",
    "RiscV64SysVFork",
    "RiscV64SysVFpathconf",
    "RiscV64SysVFsync",
    "RiscV64SysVFtruncate",
    "RiscV64SysVGetcwd",
    "RiscV64SysVGetegid",
    "RiscV64SysVGeteuid",
    "RiscV64SysVGetgid",
    "RiscV64SysVGetgroups",
    "RiscV64SysVGethostid",
    "RiscV64SysVGetlogin",
    "RiscV64SysVGetloginR",
    "RiscV64SysVGetopt",
    "RiscV64SysVGetpgid",
    "RiscV64SysVGetpgrp",
    "RiscV64SysVGetpid",
    "RiscV64SysVGetppid",
    "RiscV64SysVGetsid",
    "RiscV64SysVGetuid",
    "RiscV64SysVGetwd",
    "RiscV64SysVIsatty",
    "RiscV64SysVLchown",
    "RiscV64SysVLink",
    "RiscV64SysVLockf",
    "RiscV64SysVLseek",
    "RiscV64SysVNice",
    "RiscV64SysVPathconf",
    "RiscV64SysVPause",
    "RiscV64SysVPipe",
    "RiscV64SysVPread",
    "RiscV64SysVPthreadAtfork",
    "RiscV64SysVPwrite",
    "RiscV64SysVRead",
    "RiscV64SysVReadlink",
    "RiscV64SysVRmdir",
    "RiscV64SysVSbrk",
    "RiscV64SysVSetegid",
    "RiscV64SysVSeteuid",
    "RiscV64SysVSetgid",
    "RiscV64SysVSetpgid",
    "RiscV64SysVSetpgrp",
    "RiscV64SysVSetregid",
    "RiscV64SysVSetreuid",
    "RiscV64SysVSetsid",
    "RiscV64SysVSleep",
    "RiscV64SysVSwab",
    "RiscV64SysVSymlink",
    "RiscV64SysVSync",
    "RiscV64SysVSysconf",
    "RiscV64SysVTcgetpgrp",
    "RiscV64SysVTCsetpgrp",
    "RiscV64SysVTruncate",
    "RiscV64SysVTtyname",
    "RiscV64SysVTtynameR",
    "RiscV64SysVUlarm",
    "RiscV64SysVUnlink",
    "RiscV64SysVUsleep",
    "RiscV64SysVVfork",
    "RiscV64SysVWrite",
]
