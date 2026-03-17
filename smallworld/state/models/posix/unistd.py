import logging
import typing

from .... import emulators, exceptions
from ....platforms import Byteorder
from ..c99.utils import _emu_strlen
from ..cstd import ArgumentType, CStdModel
from ..filedesc import FDIOError, FileDescriptorManager
from .procinfo import ProcInfoManager

logger = logging.getLogger(__name__)


class FDModel(CStdModel):
    def __init__(self, address: int):
        super().__init__(address)
        self._fdmgr = FileDescriptorManager.for_platform(self.platform, self.abi)


class ProcInfoModel(CStdModel):
    def __init__(self, address: int):
        super().__init__(address)
        self._procmgr = ProcInfoManager.get()


class Access(CStdModel):
    name = "access"

    # int access(const char *, int)
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError("access() is not implemented")


class Alarm(CStdModel):
    name = "alarm"

    # unsigned int alarm(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.UINT

    # This will not actually raise a SIGALRM
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        logger.warning("Called alarm(); this will not trigger anything")
        self.set_return_value(emulator, 0)


class Brk(ProcInfoModel):
    name = "brk"

    # int brk(void *);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        new_brk = self.get_arg1(emulator)
        assert isinstance(new_brk, int)

        if self._procmgr.brk == 0:
            logger.warning(
                f"DANGER! Calling brk({hex(new_brk)}) with an uninitialized program break."
            )
            logger.warning(
                "This is probably going to cause an enormous memory allocation."
            )
            logger.warning("To avoid, please set model._procmgr.brk in your harness.")

        if new_brk > self._procmgr.brk:
            # WARNING: This can fail
            logger.warning(
                "Attempting to alter the program break from "
                f"{hex(self._procmgr.brk)} to {new_brk}"
            )
            emulator.map_memory(self._procmgr.brk, new_brk - self._procmgr.brk)

        self._procmgr.brk = new_brk
        self.set_return_value(emulator, 0)


class Chdir(ProcInfoModel):
    name = "chdir"

    # int chdir(const char *);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # This (currently) won't change CWD
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr1 = self.get_arg1(emulator)
        assert isinstance(ptr1, int)

        len1 = _emu_strlen(emulator, ptr1)

        bytes1 = emulator.read_memory(ptr1, len1)

        self._procmgr.cwd = bytes1

        self.set_return_value(emulator, 0)


class Chroot(ProcInfoModel):
    name = "chroot"

    # int chroot(const char *);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # This (currently) won't change CWD
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr1 = self.get_arg1(emulator)
        assert isinstance(ptr1, int)

        len1 = _emu_strlen(emulator, ptr1)

        bytes1 = emulator.read_memory(ptr1, len1)

        self._procmgr.root = bytes1

        self.set_return_value(emulator, 0)


class Chown(CStdModel):
    name = "chown"

    # int chown(const char *, uid_t, gid_t);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    # This won't change permissions
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr1 = self.get_arg1(emulator)
        uid = self.get_arg2(emulator)
        gid = self.get_arg3(emulator)
        assert isinstance(ptr1, int)
        assert isinstance(uid, int)
        assert isinstance(gid, int)

        len1 = _emu_strlen(emulator, ptr1)

        bytes1 = emulator.read_memory(ptr1, len1)

        filepath = bytes1.decode("utf-8")

        # TODO: actually use this to configure the directory subsystem
        logger.warning(
            f"Called chown({filepath}, {uid}, {gid}); currently does nothing"
        )

        self.set_return_value(emulator, 0)


class Close(FDModel):
    name = "close"

    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        assert isinstance(fd, int)

        try:
            self._fdmgr.close(fd)
            self.set_return_value(emulator, 0)
        except FDIOError:
            self.set_return_value(emulator, -1)


class Confstr(ProcInfoModel):
    name = "confstr"

    # size_t confstr(int, char *, len)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.SIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        name = self.get_arg1(emulator)
        dst = self.get_arg2(emulator)
        size = self.get_arg3(emulator)
        assert isinstance(name, int)
        assert isinstance(dst, int)
        assert isinstance(size, int)

        if name in self._procmgr.confstr:
            if size == 0:
                size = len(self._procmgr.confstr[name]) + 1
                self.set_return_value(emulator, size)
            else:
                out = self._procmgr.confstr[name][0 : size - 1] + b"\0"
                emulator.write_memory(dst, out)
                self.set_return_value(emulator, len(out))
        else:
            logger.warning(
                f"Called confstr with undefined name {name}; defaulting to empty string"
            )
            self.set_return_value(emulator, 0)


class Crypt(CStdModel):
    name = "crypt"

    # char *crypt(const char *key, const char *salt)
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)

        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)

        key = bytes1.decode("utf-8")
        salt = bytes2.decode("utf-8")

        logger.error(
            f"Called crypt({key}, {salt}); will now error, as this is unimplemented"
        )

        raise NotImplementedError("crypt() not implemented")


class Ctermid(ProcInfoModel):
    name = "ctermid"

    # char *ctermid(char *);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    static_space_required = 16

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        assert self.static_buffer_address is not None

        ptr = self.get_arg1(emulator)
        assert isinstance(ptr, int)

        if ptr == 0:
            ptr = self.static_buffer_address

        if len(self._procmgr.termid) >= self.static_space_required:
            raise ValueError(
                "Specified termid in ctermid model is too long;"
                f" max of {self.static_space_required - 1} bytes allowed"
            )

        emulator.write_memory(ptr, self._procmgr.termid + b"\0")

        self.set_return_value(emulator, ptr)


class Cuserid(ProcInfoModel):
    name = "cuserid"

    # char *cuserid(char *);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    static_space_required = 16

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        assert self.static_buffer_address is not None

        ptr = self.get_arg1(emulator)
        assert isinstance(ptr, int)

        if ptr == 0:
            ptr = self.static_buffer_address

        if len(self._procmgr.userid) >= self.static_space_required:
            raise ValueError(
                "Specified userid in cuserid model is too long;"
                f" max of {self.static_space_required - 1} bytes allowed"
            )

        emulator.write_memory(ptr, self._procmgr.userid + b"\0")

        self.set_return_value(emulator, ptr)


class Dup(FDModel):
    name = "dup"

    # int dup(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        old_fd = self.get_arg1(emulator)
        assert isinstance(old_fd, int)

        try:
            new_fd = self._fdmgr.dup(old_fd)
        except FDIOError:
            new_fd = -1

        self.set_return_value(emulator, new_fd)


class Dup2(FDModel):
    name = "dup2"

    # int dup2(int, int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        old_fd = self.get_arg1(emulator)
        new_fd = self.get_arg1(emulator)
        assert isinstance(old_fd, int)
        assert isinstance(new_fd, int)

        try:
            new_fd = self._fdmgr.dup(old_fd, new_fd=new_fd)
        except FDIOError:
            new_fd = -1

        self.set_return_value(emulator, new_fd)


class Encrypt(CStdModel):
    name = "encrypt"

    # void encrypt(char block[64], int edflag)
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise NotImplementedError("encrypt() is not implemented")


class Execl(CStdModel):
    name = "execl"

    # int execl(const char *, const char *, ...)
    # Variadics are a NULL-terminated sequence of char *.
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        cmd_ptr = self.get_arg1(emulator)
        arg0_ptr = self.get_arg2(emulator)

        assert isinstance(cmd_ptr, int)
        assert isinstance(arg0_ptr, int)

        cmd_len = _emu_strlen(emulator, cmd_ptr)
        cmd_bytes = emulator.read_memory(cmd_ptr, cmd_len)
        cmd = cmd_bytes.decode("utf-8")

        args = []

        varargs = self.get_varargs()
        arg_ptr = arg0_ptr
        while arg_ptr != 0:
            arg_len = _emu_strlen(emulator, arg_ptr)
            arg_bytes = emulator.read_memory(arg_ptr, arg_len)
            arg = arg_bytes.decode("utf-8")
            args.append(arg)

            _ptr = varargs.get_next_argument(ArgumentType.POINTER, emulator)
            assert isinstance(_ptr, int)
            arg_ptr = _ptr

        logger.warning(
            f"Called {self.name}({cmd}, {', '.join(args)}); erroring, since this is not modeled"
        )
        raise exceptions.UnsupportedModelError(f"{self.name}() is not modeled")


class Execle(Execl):
    name = "execle"
    # int execlp(const char *, const char *, ...)
    # Variadics are a NULL-terminated sequence of char *,
    # followed by a char *const[] for tne envp.

    # This is otherwise identical to execl.
    # It's a dud model; I'm not putting in effort to fetch envp off the back of the variadics.


class Execlp(Execl):
    name = "execlp"

    # int execlp(const char *, const char *, ...)
    # Variadics are a NULL-terminated sequence of char *.

    # This is otherwise identical to execl.


class Execv(CStdModel):
    name = "execv"

    # int execv(const char *, char *const argv[]);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        cmd_ptr = self.get_arg1(emulator)
        argv_ptr = self.get_arg2(emulator)

        assert isinstance(cmd_ptr, int)
        assert isinstance(argv_ptr, int)

        cmd_len = _emu_strlen(emulator, cmd_ptr)
        cmd_bytes = emulator.read_memory(cmd_ptr, cmd_len)
        cmd = cmd_bytes.decode("utf-8")

        assert hasattr(emulator, "platdef")

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        args = []
        arg_ptr = int.from_bytes(
            emulator.read_memory(argv_ptr, emulator.platdef.address_size), byteorder
        )
        while arg_ptr != 0:
            arg_len = _emu_strlen(emulator, arg_ptr)
            arg_bytes = emulator.read_memory(arg_ptr, arg_len)
            arg = arg_bytes.decode("utf-8")
            args.append(arg)

            argv_ptr += emulator.platdef.address_size
            assert isinstance(argv_ptr, int)
            arg_ptr = int.from_bytes(
                emulator.read_memory(argv_ptr, emulator.platdef.address_size), byteorder
            )

        logger.warning(
            f"Called {self.name}({cmd}, {', '.join(args)}); erroring, since this is not modeled"
        )
        raise exceptions.UnsupportedModelError(f"{self.name} is not modeled")


class Execvp(Execv):
    name = "execvp"
    # int execvp(const char *cmd, char *const argv[]);
    # This is otherwise identical to execv


class Execve(CStdModel):
    name = "execv"

    # int execv(const char *, char *const argv[], char *const envp[]);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        cmd_ptr = self.get_arg1(emulator)
        argv_ptr = self.get_arg2(emulator)
        envp_ptr = self.get_arg3(emulator)

        assert isinstance(cmd_ptr, int)
        assert isinstance(argv_ptr, int)
        assert isinstance(envp_ptr, int)

        cmd_len = _emu_strlen(emulator, cmd_ptr)
        cmd_bytes = emulator.read_memory(cmd_ptr, cmd_len)
        cmd = cmd_bytes.decode("utf-8")

        assert hasattr(emulator, "platdef")

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        args = []
        arg_ptr = int.from_bytes(
            emulator.read_memory(argv_ptr, emulator.platdef.address_size), byteorder
        )
        while arg_ptr != 0:
            arg_len = _emu_strlen(emulator, arg_ptr)
            arg_bytes = emulator.read_memory(arg_ptr, arg_len)
            arg = arg_bytes.decode("utf-8")
            args.append(arg)

            argv_ptr += emulator.platdef.address_size
            assert isinstance(argv_ptr, int)
            arg_ptr = int.from_bytes(
                emulator.read_memory(argv_ptr, emulator.platdef.address_size), byteorder
            )

        envs = []
        env_ptr = int.from_bytes(
            emulator.read_memory(envp_ptr, emulator.platdef.address_size), byteorder
        )
        while env_ptr != 0:
            env_len = _emu_strlen(emulator, env_ptr)
            env_bytes = emulator.read_memory(env_ptr, env_len)
            env = env_bytes.decode("utf-8")
            envs.append(env)

            envp_ptr += emulator.platdef.address_size
            assert isinstance(envp_ptr, int)
            env_ptr = int.from_bytes(
                emulator.read_memory(envp_ptr, emulator.platdef.address_size), byteorder
            )

        logger.warning(f"Called {self.name}({cmd}, {', '.join(args)}")
        env_str = "\n  ".join(envs)
        logger.warning(f"Envp: \n  {env_str}")
        logger.warning("Erroring, since this is not modeled")
        raise exceptions.UnsupportedModelError(f"{self.name} is not modeled")


# NOTE: Not modelling _exit;
# just alias the c99 model, please.


class Fchown(CStdModel):
    name = "fchown"

    # int fchown(int, uid_t, uid_t)
    argument_types = [ArgumentType.INT, ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        uid = self.get_arg2(emulator)
        gid = self.get_arg3(emulator)

        assert isinstance(fd, int)
        assert isinstance(uid, int)
        assert isinstance(gid, int)

        logger.warning(f"Called fchown({fd}, {uid}, {gid}); currently doesn nothing")

        self.set_return_value(emulator, 0)


class Fchdir(ProcInfoModel):
    name = "fchdir"

    # int fchdir(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        dirfd = self.get_arg1(emulator)
        assert isinstance(dirfd, int)

        # Does nothing.
        logger.warning(f"Called fchdir({dirfd}); will not impact cwd")
        self.set_return_value(emulator, 0)


class Fdatasync(CStdModel):
    name = "fdatasync"

    # int fdatasync(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        assert isinstance(fd, int)

        # Does nothing; we don't model this at all.
        self.set_return_value(emulator, 0)


class Fork(CStdModel):
    name = "fork"

    # int fork()
    argument_types = []
    return_type = ArgumentType.INT

    def __init__(self, address: int):
        super().__init__(address)
        self.error = False
        self.follow_parent = True

    # We have no actual model of forking,
    # and no actual model of multiple processes.
    # Many of the process info calls will change their behavior across a fork
    # and we don't model that.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        if self.error:
            logger.warning("Calling fork(); simulating an error")
            self.set_return_value(emulator, -1)
        elif self.follow_parent:
            logger.warning("Calling fork(); simulating returning to the parent")
            self.set_return_value(emulator, 42)
        else:
            logger.warning("Calling fork(); simulating returning to the child")
            self.set_return_value(emulator, 0)


class Fpathconf(CStdModel):
    name = "fpathconf"

    # long fpathconf(int, int)
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.LONG

    # This is possible to implement,
    # but would require some complex modeling.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        name = self.get_arg2(emulator)

        assert isinstance(fd, int)
        assert isinstance(name, int)

        # imprecise: just return 0.
        logger.warning(f"Called fpathconf({fd}, {name}); returning zero")
        self.set_return_value(emulator, 0)


class Fsync(CStdModel):
    name = "fsync"

    # int fsync(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        assert isinstance(fd, int)

        # Does nothing; we don't model this at all.
        self.set_return_value(emulator, 0)


class Ftruncate(CStdModel):
    name = "ftruncate"

    # int ftruncate(int, off_t)
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        size = self.get_arg2(emulator)

        assert isinstance(fd, int)
        assert isinstance(size, int)

        logger.warning(f"Called ftruncate({fd}, {size}); not actually modeled")
        self.set_return_value(emulator, 0)


class Getcwd(ProcInfoModel):
    name = "getcwd"

    # char *getcwd(char *, size_t)
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)
        size = self.get_arg2(emulator)
        assert isinstance(ptr, int)
        assert isinstance(size, int)

        if len(self._procmgr.cwd) + 1 > size:
            self.set_return_value(emulator, 0)
        else:
            emulator.write_memory(ptr, self._procmgr.cwd + b"\0")
            self.set_return_value(emulator, ptr)


class Getegid(ProcInfoModel):
    name = "getegid"

    # gid_t getegid()
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        self.set_return_value(emulator, self._procmgr.egid)


class Geteuid(ProcInfoModel):
    name = "geteuid"

    # uid_t geteuid()
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        self.set_return_value(emulator, self._procmgr.euid)


class Getgid(ProcInfoModel):
    name = "getgid"

    # gid_t getgid()
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        self.set_return_value(emulator, self._procmgr.gid)


class Getgroups(ProcInfoModel):
    name = "getgroups"

    # int getgroups(int, gid_t [])
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        size = self.get_arg1(emulator)
        ptr = self.get_arg2(emulator)

        assert isinstance(size, int)
        assert isinstance(ptr, int)

        byteorder: typing.Literal["big", "little"]
        if self.platform.byteorder == Byteorder.BIG:
            byteorder = "big"
        else:
            byteorder = "little"

        if size == 0:
            self.set_return_value(emulator, len(self._procmgr.groups))
        elif len(self._procmgr.groups) > size:
            self.set_return_value(emulator, -1)
        else:
            for gid in self._procmgr.groups:
                group_bytes = gid.to_bytes(4, byteorder)
                emulator.write_memory(ptr, group_bytes)
                ptr += 4

            self.set_return_value(emulator, len(self._procmgr.groups))


class Gethostid(ProcInfoModel):
    name = "gethostid"

    # long gethostid()
    argument_types = []
    return_type = ArgumentType.LONG

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        self.set_return_value(emulator, self._procmgr.hostid)


class Getlogin(ProcInfoModel):
    name = "getlogin"

    # char *getlogin()
    argument_types = []
    return_type = ArgumentType.POINTER

    static_space_required = 16

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        assert self.static_buffer_address is not None

        if len(self._procmgr.login) >= self.static_space_required:
            raise ValueError(
                "Specified login in getlogin model is too long;"
                f" max of {self.static_space_required - 1} bytes allowed"
            )

        emulator.write_memory(self.static_buffer_address, self._procmgr.login + b"\0")
        self.set_return_value(emulator, self.static_buffer_address)


class GetloginR(ProcInfoModel):
    # int *getlogin_r(char *, size_t)
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)
        size = self.get_arg2(emulator)
        assert isinstance(ptr, int)
        assert isinstance(size, int)

        if len(self._procmgr.login) >= size:
            self.set_return_value(emulator, -1)
        else:
            emulator.write_memory(ptr, self._procmgr.login + b"\0")
            self.set_return_value(emulator, 0)


class Getopt(CStdModel):
    name = "getopt"

    # int getopt(int, char *const[], const char *)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # This relies on extern'd variables to return information.
        # Possible to model, but SmallWorld doesn't have the facility yet
        raise exceptions.UnsupportedModelError(f"{self.name}() is not modeled")


class Getpgid(ProcInfoModel):
    name = "getpgid"

    # pid_t getpgid(pid_t)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        pid = self.get_arg1(emulator)
        assert isinstance(pid, int)

        if pid == self._procmgr.pid:
            # We can answer about our own pid
            self.set_return_value(emulator, self._procmgr.pgrp)
        else:
            logger.warning(f"Tried to get process group ID for {pid}, which is not us.")
            self.set_return_value(emulator, -1)


class Getpgrp(ProcInfoModel):
    name = "getpgrp"

    # pid_t getpgrp()
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        self.set_return_value(emulator, self._procmgr.pgrp)


class Getpid(ProcInfoModel):
    name = "getpid"

    # pid_t getpid()
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        self.set_return_value(emulator, self._procmgr.pid)


class Getppid(ProcInfoModel):
    name = "getppid"

    # pid_t getppid()
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        self.set_return_value(emulator, self._procmgr.ppid)


class Getsid(ProcInfoModel):
    name = "getsid"

    # pid_t getsid()
    argument_types = []
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # I don't think we have enough info to answer this
        logger.warning("Executed getsid(); returning -1")
        self.set_return_value(emulator, -1)


class Getuid(ProcInfoModel):
    name = "getuid"

    # pid_t getuid()
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        self.set_return_value(emulator, self._procmgr.uid)


class Getwd(ProcInfoModel):
    name = "getwd"

    # char *getwd(char *)
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)
        assert isinstance(ptr, int)

        if len(self._procmgr.cwd) >= 4096:
            self.set_return_value(emulator, 0)
        else:
            emulator.write_memory(ptr, self._procmgr.cwd)
            self.set_return_value(emulator, ptr)


class Isatty(CStdModel):
    name = "isatty"

    # int isatty(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        assert isinstance(fd, int)

        # FIXME: I can probably do better.
        logger.warning(f"Called isatty({fd}); assume 0 - 2 are ttys")
        if fd >= 0 and fd <= 2:
            self.set_return_value(emulator, 1)
        else:
            self.set_return_value(emulator, 0)


class Lchown(CStdModel):
    name = "lchown"

    # int lchown(char *, uid_t, gid_t)
    argument_types = [ArgumentType.POINTER, ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr1 = self.get_arg1(emulator)
        uid = self.get_arg2(emulator)
        gid = self.get_arg3(emulator)
        assert isinstance(ptr1, int)
        assert isinstance(uid, int)
        assert isinstance(gid, int)

        len1 = _emu_strlen(emulator, ptr1)
        bytes1 = emulator.read_memory(ptr1, len1)
        path1 = bytes1.decode("utf-8")

        # TODO: actually use this to configure the directory subsystem
        logger.warning(f"Called lchown({path1}, {uid}, {gid}); currently does nothing")
        self.set_return_value(emulator, 0)


class Link(CStdModel):
    name = "link"

    # int link(char *, char *)
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)
        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)
        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)
        path1 = bytes1.decode("utf-8")
        path2 = bytes2.decode("utf-8")

        logger.warning(f"Called link({path1}, {path2}); currently does nothing")
        self.set_return_value(emulator, 0)


class Lockf(CStdModel):
    name = "lockf"

    # int lockf(int, int, off_t)
    argument_types = [ArgumentType.INT, ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        fd = self.get_arg1(emulator)
        function = self.get_arg2(emulator)
        offset = self.get_arg3(emulator)
        assert isinstance(fd, int)
        assert isinstance(function, int)
        assert isinstance(offset, int)

        logger.warning(
            f"Called lockf({fd}, {function}, {offset}); currently does nothing"
        )
        self.set_return_value(emulator, 0)


class Lseek(FDModel):
    name = "lseek"

    # off_t lseek(int, off_t, int)
    argument_types = [ArgumentType.INT, ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        fd = self.get_arg1(emulator)
        offset = self.get_arg2(emulator)
        whence = self.get_arg3(emulator)
        assert isinstance(fd, int)
        assert isinstance(offset, int)
        assert isinstance(whence, int)

        try:
            file = self._fdmgr.get(fd)
        except FDIOError:
            self.set_return_value(emulator, -1)
            return

        pos = file.seek(offset, whence)
        self.set_return_value(emulator, pos)


class Nice(ProcInfoModel):
    name = "nice"

    # int nice(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        incr = self.get_arg1(emulator)
        assert isinstance(incr, int)

        new_nice = self._procmgr.nice + incr
        if new_nice < 0 or new_nice > 39:
            self.set_return_value(emulator, -1)
        self._procmgr.nice = new_nice
        self.set_return_value(emulator, new_nice - 20)


class Pathconf(CStdModel):
    name = "pathconf"

    # long pathconf(const char *, int)
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.LONG

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr1 = self.get_arg1(emulator)
        name = self.get_arg2(emulator)
        assert isinstance(ptr1, int)
        assert isinstance(name, int)

        len1 = _emu_strlen(emulator, ptr1)
        bytes1 = emulator.read_memory(ptr1, len1)
        path1 = bytes1.decode("utf-8")

        logger.warning(f"Called pathconf({path1}, {name}); returning 0")
        self.set_return_value(emulator, 0)


class Pause(CStdModel):
    name = "pause"

    # int pause()
    argument_types = []
    return_type = ArgumentType.INT

    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Pause halts execution until a signal happens.
        # We don't have signals, and thus can't support this.
        raise exceptions.UnsupportedModelError("pause() is unsupported")


class Pipe(FDModel):
    name = "pipe"

    # int pipe(int[2])
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # This is hypothetically possible,
        # but I don't have the backing data structure for it.
        raise NotImplementedError("pipe() not implemented")


class Pread(FDModel):
    name = "pread"

    # ssize_t pread(int, void *, size_t, off_t)
    argument_types = [
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.INT,
    ]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        buf = self.get_arg2(emulator)
        size = self.get_arg3(emulator)
        off = self.get_arg4(emulator)

        assert isinstance(fd, int)
        assert isinstance(buf, int)
        assert isinstance(size, int)
        assert isinstance(off, int)

        try:
            file = self._fdmgr.get(fd)

            cursor = file.cursor
            file.seek(off, 0)
            data = file.read(size)
            file.seek(cursor, 0)

            emulator.write_memory(buf, data)
            self.set_return_value(emulator, len(data))
        except FDIOError:
            self.set_return_value(emulator, -1)


class PthreadAtfork(CStdModel):
    name = "pthread_atfork"

    # int pthread_atfork(void (*)(void), void (*)(void))
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # This registers function calls to be invoked when fork happens.
        # In theory, I could model this.
        logger.warning("Called pthread_atfork(); returning 0")
        self.set_return_value(emulator, 0)


class Pwrite(FDModel):
    name = "pwrite"

    # ssize_t pwrite(int, const void *, size_t, off_t)
    argument_types = [
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.INT,
    ]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        buf = self.get_arg2(emulator)
        size = self.get_arg3(emulator)
        off = self.get_arg4(emulator)

        assert isinstance(fd, int)
        assert isinstance(buf, int)
        assert isinstance(size, int)
        assert isinstance(off, int)

        data = emulator.read_memory(buf, size)

        try:
            file = self._fdmgr.get(fd)

            cursor = file.cursor
            file.seek(off, 0)
            file.write(data)
            file.seek(cursor, 0)

            self.set_return_value(emulator, len(data))
        except FDIOError:
            self.set_return_value(emulator, -1)


class Read(FDModel):
    name = "read"

    # ssize_t read(int, void *, size_t)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        buf = self.get_arg2(emulator)
        size = self.get_arg3(emulator)

        assert isinstance(fd, int)
        assert isinstance(buf, int)
        assert isinstance(size, int)

        try:
            file = self._fdmgr.get(fd)
            data = file.read(size)
            emulator.write_memory(buf, data)
            self.set_return_value(emulator, len(data))
        except FDIOError:
            self.set_return_value(emulator, -1)


class Readlink(CStdModel):
    name = "readlink"

    # int readlink(const char *, char *, size_t)
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        src = self.get_arg1(emulator)
        dst = self.get_arg2(emulator)
        size = self.get_arg3(emulator)
        assert isinstance(src, int)
        assert isinstance(dst, int)
        assert isinstance(size, int)

        len1 = _emu_strlen(emulator, src)
        bytes1 = emulator.read_memory(src, len1)
        path1 = bytes1.decode("utf-8")

        logger.warning(
            f"Called readlink({path1}, {hex(dst)}, {size}); assuming not a symlink"
        )
        self.set_return_value(emulator, -1)


class Rmdir(CStdModel):
    name = "rmdir"

    # int rmdir(char *)
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr1 = self.get_arg1(emulator)
        assert isinstance(ptr1, int)

        len1 = _emu_strlen(emulator, ptr1)
        bytes1 = emulator.read_memory(ptr1, len1)
        path1 = bytes1.decode("utf-8")

        logger.warning(f"Called rmdir({path1}); not doing anything")
        self.set_return_value(emulator, 0)


class Sbrk(ProcInfoModel):
    name = "sbrk"

    # void *sbrk(ssize_t incr)
    argument_types = [ArgumentType.SSIZE_T]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        incr = self.get_arg1(emulator)
        assert isinstance(incr, int)

        if self._procmgr.brk == 0:
            logger.warning(
                f"DANGER! Calling sbrk({incr}) with an uninitialized program break."
            )
            logger.warning(
                "This is probably going to cause an enormous memory allocation."
            )
            logger.warning("To avoid, please set model._procmgr.brk in your harness.")

        new_brk = self._procmgr.brk + incr
        if new_brk > self._procmgr.brk:
            # WARNING: This can fail
            logger.warning(
                "Attempting to alter the program break from "
                f"{hex(self._procmgr.brk)} to {new_brk}"
            )
            emulator.map_memory(self._procmgr.brk, incr)

        self._procmgr.brk = new_brk
        self.set_return_value(emulator, new_brk)


class Setegid(ProcInfoModel):
    name = "setegid"

    # int setegid(gid_t)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        egid = self.get_arg1(emulator)
        assert isinstance(egid, int)

        self._procmgr.egid = egid
        self.set_return_value(emulator, 0)


class Seteuid(ProcInfoModel):
    name = "seteuid"

    # int seteuid(gid_t)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        euid = self.get_arg1(emulator)
        assert isinstance(euid, int)

        self._procmgr.euid = euid
        self.set_return_value(emulator, 0)


class Setgid(ProcInfoModel):
    name = "setgid"

    # int setgid(gid_t)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        gid = self.get_arg1(emulator)
        assert isinstance(gid, int)

        self._procmgr.gid = gid
        self.set_return_value(emulator, 0)


class Setpgid(ProcInfoModel):
    name = "setpgid"

    # int setgid(pid_t, pid_t)
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        pid = self.get_arg1(emulator)
        pgrp = self.get_arg2(emulator)
        assert isinstance(pid, int)
        assert isinstance(pgrp, int)

        if pid == self._procmgr.pid:
            # We can set our own pgrp
            self._procmgr.pgrp = pgrp
            self.set_return_value(emulator, 0)
        else:
            logger.warning(f"Tried to set process group ID for {pid}, which is not us.")
            self.set_return_value(emulator, -1)


class Setpgrp(ProcInfoModel):
    name = "setpgrp"

    # int setpgrp()
    # NOTE: There are different specs for this one.
    # The GNU man pages say this returns 0 on success.
    # Other man pages say it returns the pid.
    argument_types = []
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # TODO: I think this is right...
        self._procmgr.pgrp = self._procmgr.pid

        self.set_return_value(emulator, 0)


class Setregid(ProcInfoModel):
    name = "setregid"

    # int setregid(gid_t, gid_t)
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        gid = self.get_arg1(emulator)
        egid = self.get_arg2(emulator)

        assert isinstance(gid, int)
        assert isinstance(egid, int)

        if gid != -1:
            self._procmgr.gid = gid
        if egid != -1:
            self._procmgr.egid = egid
        self.set_return_value(emulator, 0)


class Setreuid(ProcInfoModel):
    name = "setreuid"

    # int setreuid(uid_t, uid_t)
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        uid = self.get_arg1(emulator)
        euid = self.get_arg2(emulator)

        assert isinstance(uid, int)
        assert isinstance(euid, int)

        if uid != -1:
            self._procmgr.uid = uid
        if euid != -1:
            self._procmgr.euid = euid
        self.set_return_value(emulator, 0)


class Setsid(ProcInfoModel):
    name = "setsid"

    # pid_t setsid()
    argument_types = []
    return_type = ArgumentType.INT

    # This can fail if not enough permissions.
    # We don't model those permissions.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        self.set_return_value(emulator, self._procmgr.pid)


class Sleep(CStdModel):
    name = "sleep"

    # unsigned int sleep(unsigned int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        self.set_return_value(emulator, 0)


class Swab(CStdModel):
    name = "swab"

    # void swab(const void *, void *, ssize_t)
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SSIZE_T]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        src = self.get_arg1(emulator)
        dst = self.get_arg2(emulator)
        size = self.get_arg3(emulator)

        assert isinstance(src, int)
        assert isinstance(dst, int)
        assert isinstance(size, int)

        if size < 0:
            # Does nothing on negative size.
            # Why do we even have that lever?
            return

        # swab()'s behavior for the last byte
        # is technically undefined if size is odd.
        # Be nice, and just leave it alone.
        for i in range(0, size, 2):
            data = emulator.read_memory(src + i, 2)
            data = bytes([data[1], data[0]])
            emulator.write_memory(dst + i, 2)


class Symlink(CStdModel):
    name = "symlink"

    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr1 = self.get_arg1(emulator)
        ptr2 = self.get_arg2(emulator)
        assert isinstance(ptr1, int)
        assert isinstance(ptr2, int)

        len1 = _emu_strlen(emulator, ptr1)
        len2 = _emu_strlen(emulator, ptr2)
        bytes1 = emulator.read_memory(ptr1, len1)
        bytes2 = emulator.read_memory(ptr2, len2)
        path1 = bytes1.decode("utf-8")
        path2 = bytes2.decode("utf-8")

        logger.warning(f"Called symlink({path1}, {path2}); currently does nothing")
        self.set_return_value(emulator, 0)


class Sync(CStdModel):
    name = "sync"

    # void sync()
    argument_types = []
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # We don't model storage synchronization.
        self.set_return_value(emulator, 0)


class Sysconf(ProcInfoModel):
    name = "sysconf"

    # long int sysconf(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.LONG

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        name = self.get_arg1(emulator)
        assert isinstance(name, int)

        if name in self._procmgr.sysconf:
            self.set_return_value(emulator, self._procmgr.sysconf[name])
        else:
            logger.warning(
                f"Called sysconf with undefined name {name}; defaulting to -1"
            )
            self.set_return_value(emulator, -1)


class Tcgetpgrp(ProcInfoModel):
    name = "tcgetpgrp"

    # pid_t tcgetpgrp(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Assume we are the controlling process
        self.set_return_value(emulator, self._procmgr.pgrp)


class TCsetpgrp(ProcInfoModel):
    name = "tcsetpgrp"

    # pid_t tcsetpgrp(int, pid_t)
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        pgrp = self.get_arg2(emulator)
        assert isinstance(pgrp, int)

        # Assume we are the controlling process
        self._procmgr.pgrp = pgrp
        self.set_return_value(emulator, 0)


class Truncate(FDModel):
    name = "truncate"
    # int ftruncate(char *, off_t)
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr1 = self.get_arg1(emulator)
        size = self.get_arg2(emulator)

        assert isinstance(ptr1, int)
        assert isinstance(size, int)

        len1 = _emu_strlen(emulator, ptr1)
        bytes1 = emulator.read_memory(ptr1, len1)
        filepath = bytes1.decode("utf-8")

        logger.warning(f"Called ftruncate({filepath}, {size}); not actually modeled")
        self.set_return_value(emulator, 0)


class Ttyname(FDModel):
    name = "ttyname"

    # char *ttyname(int)
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.POINTER

    # This should fail if the FD is not a tty.
    # We don't model that correctly.
    imprecise = True

    static_space_needed = 16

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        assert self.static_buffer_address is not None

        fd = self.get_arg1(emulator)
        assert isinstance(fd, int)

        if fd >= 0 or fd <= 2:
            try:
                file = self._fdmgr.get(fd)
                out = (
                    file.name.encode("utf-8")[0 : self.static_space_needed - 1] + b"\0"
                )
                emulator.write_memory(self.static_buffer_address, out)
                self.set_return_value(emulator, self.static_buffer_address)
            except FDIOError:
                self.set_return_value(emulator, 0)
        else:
            self.set_return_value(emulator, 0)


class TtynameR(FDModel):
    name = "ttyname_r"

    # char *ttyname(int)
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    # This should fail if the FD is not a tty.
    # We don't model that correctly.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        ptr = self.get_arg2(emulator)
        size = self.get_arg3(emulator)
        assert isinstance(fd, int)
        assert isinstance(ptr, int)
        assert isinstance(size, int)

        if fd >= 0 or fd <= 2:
            try:
                file = self._fdmgr.get(fd)
                out = file.name.encode("utf-8") + b"\0"
                if len(out) > size:
                    self.set_return_value(emulator, -1)
                else:
                    emulator.write_memory(ptr, out)
                    self.set_return_value(emulator, 0)
            except FDIOError:
                self.set_return_value(emulator, -1)
        else:
            self.set_return_value(emulator, -1)


class Ularm(CStdModel):
    name = "ualarm"

    # useconds_t ualarm(useconds_t, useconds_t)
    argument_types = [ArgumentType.ULONG, ArgumentType.ULONG]
    return_type = ArgumentType.ULONG

    # This will not actually raise a SIGALRM
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        logger.warning("Called ualarm(); this will not trigger anything")
        self.set_return_value(emulator, 0)


class Unlink(CStdModel):
    name = "unlink"

    # int unlink(char *)
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # This will not actually delete the file
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr1 = self.get_arg1(emulator)
        assert isinstance(ptr1, int)

        len1 = _emu_strlen(emulator, ptr1)
        bytes1 = emulator.read_memory(ptr1, len1)
        path1 = bytes1.decode("utf-8")

        logger.warning(f"Called unlink({path1}); not doing anything")
        self.set_return_value(emulator, 0)


class Usleep(CStdModel):
    name = "usleep"

    # useconds_t usleep(useconds_t)
    argument_types = [ArgumentType.ULONG]
    return_type = ArgumentType.ULONG

    # This will not actually raise a SIGALRM
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        logger.warning("Called usleep(); this will not trigger anything")
        self.set_return_value(emulator, 0)


class Vfork(CStdModel):
    name = "vfork"

    # int fork()
    argument_types = []
    return_type = ArgumentType.INT

    def __init__(self, address: int):
        super().__init__(address)
        self.error = False
        self.follow_parent = True

    # We have no actual model of forking,
    # and no actual model of multiple processes.
    # Many of the process info calls will change their behavior across a fork
    # and we don't model that.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.error:
            logger.warning("Calling vfork(); simulating an error")
            self.set_return_value(emulator, -1)
        elif self.follow_parent:
            logger.warning("Calling vfork(); simulating returning to the child")
            self.set_return_value(emulator, 42)
        else:
            logger.warning("Calling vfork(); simulating returning to the child")
            self.set_return_value(emulator, 0)


class Write(FDModel):
    name = "write"

    # ssize_t write(int, const void *, size_t, off_t)
    argument_types = [
        ArgumentType.INT,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.INT,
    ]
    return_type = ArgumentType.SSIZE_T

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        fd = self.get_arg1(emulator)
        buf = self.get_arg2(emulator)
        size = self.get_arg3(emulator)

        assert isinstance(fd, int)
        assert isinstance(buf, int)
        assert isinstance(size, int)

        data = emulator.read_memory(buf, size)

        try:
            file = self._fdmgr.get(fd)
            file.write(data)
            self.set_return_value(emulator, len(data))
        except FDIOError:
            self.set_return_value(emulator, -1)


__all__ = [
    "Access",
    "Alarm",
    "Brk",
    "Chdir",
    "Chroot",
    "Chown",
    "Close",
    "Confstr",
    "Crypt",
    "Ctermid",
    "Cuserid",
    "Dup",
    "Dup2",
    "Encrypt",
    "Execl",
    "Execle",
    "Execlp",
    "Execv",
    "Execvp",
    "Execve",
    "Fchown",
    "Fchdir",
    "Fdatasync",
    "Fork",
    "Fpathconf",
    "Fsync",
    "Ftruncate",
    "Getcwd",
    "Getegid",
    "Geteuid",
    "Getgid",
    "Getgroups",
    "Gethostid",
    "Getlogin",
    "GetloginR",
    "Getopt",
    "Getpgid",
    "Getpgrp",
    "Getpid",
    "Getppid",
    "Getsid",
    "Getuid",
    "Getwd",
    "Isatty",
    "Lchown",
    "Link",
    "Lockf",
    "Lseek",
    "Nice",
    "Pathconf",
    "Pause",
    "Pipe",
    "Pread",
    "PthreadAtfork",
    "Pwrite",
    "Read",
    "Readlink",
    "Rmdir",
    "Sbrk",
    "Setegid",
    "Seteuid",
    "Setgid",
    "Setpgid",
    "Setpgrp",
    "Setregid",
    "Setreuid",
    "Setsid",
    "Sleep",
    "Swab",
    "Symlink",
    "Sync",
    "Sysconf",
    "Tcgetpgrp",
    "TCsetpgrp",
    "Truncate",
    "Ttyname",
    "TtynameR",
    "Ularm",
    "Unlink",
    "Usleep",
    "Vfork",
    "Write",
]
