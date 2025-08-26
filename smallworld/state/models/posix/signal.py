import typing

from .... import emulators
from ....platforms import Architecture
from ..c99.signal import Signal
from ..cstd import ArgumentType, CStdModel

# NOTE: signal() and raise() are defined in C99

# NOTE: pid_t is defined as int in all supported ABIs.
# NOTE: pthread_t is defined as unsigned long in all supported ABIs.

# NOTE: glibc and POSIX actively disagree about sigmask_t
# POSIX headers define sigmask_t as a 128-byte type.
# glibc only uses the first eight bytes;
# it doesn't touch the trailing 120 bytes.


class BsdSignal(Signal):
    # NOTE: This is signal() with slightly different semantics.
    #
    # The C99 specification made some rather unilateral decisions
    # regarding what should happen when a signal handler fires.
    #
    # The BSD community disagreed with the System V community,
    # and made their own unilateral decisions
    # which are enshrined in the API for this function.
    #
    # The System V community fired back with the non-standard
    # sysv_signal() function.
    #
    # POSIX fixed this by introducing sigaction(),
    # which lets you control all of these decisions for yourself.
    #
    # This is why there are warnings everywhere saying
    # "don't use signal() except with pre-defined handlers".
    name = "bsd_signal"

    # typedef void (*sighandler_t)(int);
    # sighandler_t bsd_signal(int sig, sighandler_t func);


class Kill(CStdModel):
    name = "kill"

    # int kill(pid_t pid, int sig);
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    # Most of our emulators can't model signals.
    # I'm not sure it's possible to model raising one.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class Killpg(CStdModel):
    name = "killpg"

    # int killpg(int pgid, int sig);
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    # Most of our emulators can't model signals.
    # I'm not sure it's possible to model raising one.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class PthreadKill(CStdModel):
    name = "pthread_kill"

    # int pthread_kill(pthread_t thread, int sig);
    argument_types = [ArgumentType.ULONG, ArgumentType.INT]
    return_type = ArgumentType.INT

    # Most of our emulators can't model signals.
    # I'm not sure it's possible to model raising one.
    # We currently have no plans to model multithreading.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class PthreadSigmask(CStdModel):
    name = "pthread_sigmask"

    # int pthread_sigmask(int how, sigset_t *set, sigset_t *oldset);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # We currently have no plans to model multithreading.
    # This model assumes a single thread,
    # since I have no concept of a current TID.
    imprecise = True

    # NOTE: This assumes a null initial signal mask.

    # TODO: This won't interoperate with sigprocmask()
    # You're not supposed to interoperate the two,
    # so I'm okay with this for now.

    def __init__(self, address: int):
        super().__init__(address)
        self.sigmask = b"\0" * 128

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        how = self.get_arg1(emulator)
        newset = self.get_arg2(emulator)
        oldset = self.get_arg3(emulator)

        assert isinstance(how, int)
        assert isinstance(newset, int)
        assert isinstance(oldset, int)

        # sigset_t is a 1024-bit bit vector.
        # It's split up differently in different ABIs, but that's what it amounts to.

        # TODO: This syscall actually handles out-of-bounds addresses
        # Do we want to model this, or leave the error to let harness authors know?

        if newset != 0:
            # Read the new vector out of memory.
            # If this thing has alignment issues, I will make ugly noises.
            newvec = emulator.read_memory(newset, 128)

            if how == 0:
                # Case: how == SIG_BLOCK: Set sigmask to newvec | sigmask
                self.sigmask = bytes(
                    map(lambda x: self.sigmask[x] | newvec[x], range(0, 128))
                )
            elif how == 1:
                # Case: how == SIG_UNBLOCK: Set sigmask to ~newvec | sigmask
                self.sigmask = bytes(
                    map(lambda x: self.sigmask[x] | ~newvec[x], range(0, 128))
                )
            elif how == 2:
                # Case: how == SIG_SETMASK: Set sigmask to newvec
                self.sigmask = newvec
            else:
                # Case: default: Return failure
                self.set_return_value(emulator, -1)
                return

        if oldset != 0:
            # If oldset is set, save the sigmask to it.
            emulator.write_memory(oldset, self.sigmask)


class Sigaction(CStdModel):
    name = "sigaction"

    # typedef void (*sighandler_t)(int);
    # int sigaction(int sig, const struct sigaction *act, const struct sigaction *oldact);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # FIXME: This doesn't interoperate with signal()
    # Programs generally shouldn't use signal(), but they can use it to clear a handler.

    # Most of our emulators can't model signals
    imprecise = True

    def __init__(self, address: int):
        super().__init__(address)
        # Track any registered handlers.
        # Sometimes programs care about this.
        self.handlers: typing.Dict[int, int] = dict()
        self.flags: typing.Dict[int, int] = dict()
        self.masks: typing.Dict[int, bytes] = dict()

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        sig = self.get_arg1(emulator)
        act = self.get_arg2(emulator)
        oldact = self.get_arg3(emulator)

        assert isinstance(sig, int)
        assert isinstance(act, int)
        assert isinstance(oldact, int)

        # Figure out field alignments in the sigaction struct.
        # Of course MIPS has to be different.
        if self.platform.architecture == Architecture.MIPS32:
            handler_off = 0x4
            mask_off = 0x8
            flags_off = 0x0
        elif self.platform.architecture == Architecture.MIPS64:
            handler_off = 0x8
            mask_off = 0x10
            flags_off = 0x0
        elif ArgumentType.LONG in self._four_byte_types:
            handler_off = 0x0
            mask_off = 0x4
            flags_off = 0x84
        else:
            handler_off = 0x0
            mask_off = 0x8
            flags_off = 0x88

        # Get the old handler details out of this model
        oldhandler = self.handlers.get(sig, 0)
        oldmask = self.masks.get(sig, b"\0" * 128)
        oldflags = self.flags.get(sig, 0)

        if act != 0:
            # If act is non-null, set the handler to its current contents
            newhandler = self.read_integer(
                act + handler_off, ArgumentType.POINTER, emulator
            )
            newmask = emulator.read_memory(act + mask_off, 128)
            newflags = self.read_integer(act + flags_off, ArgumentType.UINT, emulator)

            self.handlers[sig] = newhandler
            self.masks[sig] = newmask
            self.flags[sig] = newflags

        if oldact != 0:
            # If oldact is non-null, populate it with the old handler info
            self.write_integer(
                oldact + handler_off, oldhandler, ArgumentType.POINTER, emulator
            )
            emulator.write_memory(oldact + mask_off, oldmask)
            self.write_integer(
                oldact + flags_off, oldflags, ArgumentType.UINT, emulator
            )

        self.set_return_value(emulator, 0)


class Sigaddset(CStdModel):
    name = "sigaddset"

    # int sigaddset(sigset_t *set, int sig);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)
        idx = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(idx, int)

        # NOTE: This uses glibc's model of how this works.
        # This only supports 64 signals for most platforms,
        # 128 for MIPS.
        max_idx = 64
        if self.platform.architecture in (Architecture.MIPS32, Architecture.MIPS64):
            max_idx = 128

        if idx < 0 or idx >= max_idx:
            # Bad signal number
            self.set_return_value(emulator, -1)
            return

        if ArgumentType.LONG in self._four_byte_types:
            bitoff = idx % 32
            wordoff = idx // 32
            wordsize = 4
        else:
            bitoff = idx % 64
            wordoff = idx // 64
            wordsize = 8

        # Read the specific word storing our bit.
        # The array is LSW-first, but the words are in native byte order.
        # Technically they're longs, but it's easier to handle them as ulongs.
        word = self.read_integer(
            ptr + (wordoff * wordsize), ArgumentType.ULONG, emulator
        )
        word |= 1 << bitoff
        self.write_integer(
            ptr + (wordoff * wordsize), word, ArgumentType.ULONG, emulator
        )

        self.set_return_value(emulator, 0)


class Sigaltstack(CStdModel):
    name = "sigaltstack"

    # int sigaltstack(const stack_t *stack, stack_t *oldstack);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # All none of the modeled signals will use the alternate stack.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class Sigdelset(CStdModel):
    name = "sigdelset"

    # int sigdelset(sigset_t *set, int sig);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)
        idx = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(idx, int)

        # NOTE: This uses glibc's model of how this works.
        # This only supports 64 signals for most platforms,
        # 128 for MIPS.
        max_idx = 64
        if self.platform.architecture in (Architecture.MIPS32, Architecture.MIPS64):
            max_idx = 128

        if idx < 0 or idx >= max_idx:
            # Bad signal number
            self.set_return_value(emulator, -1)
            return

        if ArgumentType.LONG in self._four_byte_types:
            bitoff = idx % 32
            wordoff = idx // 32
            wordsize = 4
        else:
            bitoff = idx % 64
            wordoff = idx // 64
            wordsize = 8

        # Read the specific word storing our bit.
        # The array is LSW-first, but the words are in native byte order.
        # Technically they're longs, but it's easier to handle them as ulongs.
        word = self.read_integer(
            ptr + (wordoff * wordsize), ArgumentType.ULONG, emulator
        )
        word &= ~(1 << bitoff)
        self.write_integer(
            ptr + (wordoff * wordsize), word, ArgumentType.ULONG, emulator
        )

        self.set_return_value(emulator, 0)


class Sigemptyset(CStdModel):
    name = "sigemptyset"

    # int sigemptyset(sigset_t *set);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        # NOTE: This follows the GNU standard.
        # GNU only uses the first few bytes of a sigset_t.
        emulator.write_memory(ptr, b"\0" * 8)

        # Of course MIPS is different
        if self.platform.architecture in (Architecture.MIPS32, Architecture.MIPS64):
            emulator.write_memory(ptr + 8, b"\0" * 8)

        self.set_return_value(emulator, 0)


class Sigfillset(CStdModel):
    name = "sigfillset"

    # int sigfillset(sigset_t *set);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        # NOTE: This follows the GNU standard.
        # GNU only uses the first few bytes of a sigset_t.
        # It also excludes two real-time signals.

        if ArgumentType.LONG in self._four_byte_types:
            # I'd love to use ulonglong, but the word ordering isn't endian-dependent.
            self.write_integer(ptr, 0x7FFFFFFF, ArgumentType.ULONG, emulator)
            self.write_integer(ptr + 4, 0xFFFFFFFE, ArgumentType.ULONG, emulator)
        else:
            self.write_integer(ptr, 0xFFFFFFFE7FFFFFFF, ArgumentType.ULONG, emulator)

        # Of course MIPS is different.
        if self.platform.architecture in (Architecture.MIPS32, Architecture.MIPS64):
            # All bits are set, so it doesn't matter how I write this.
            self.write_integer(
                ptr + 8, 0xFFFFFFFFFFFFFFFF, ArgumentType.ULONGLONG, emulator
            )

        self.set_return_value(emulator, 0)


class Sighold(CStdModel):
    name = "sighold"

    # int sighold(int sig);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    # This is part of a historical System V signal handler.
    # Unlike sigaction and sigprocmask,
    # it's not easy to localize across functions.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class Sigignore(CStdModel):
    name = "sigignore"

    # int sigignore(int sig);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    # This is part of a historical System V signal handler.
    # Unlike sigaction and sigprocmask,
    # it's not easy to localize across functions.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class Siginterrupt(CStdModel):
    name = "siginterrupt"

    # int siginterrupt(int sig, int flag);
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.INT

    # This is part of a historical System V signal handler.
    # Unlike sigaction and sigprocmask,
    # it's not easy to localize across functions.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class Sigismember(CStdModel):
    name = "sigismember"

    # int sigismember(sigset_t *set, int sig);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)


class Sigpause(CStdModel):
    name = "sigpause"

    # int sigpause(int arg);
    argument_types = [ArgumentType.POINTER, ArgumentType.INT]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # This one's fun.  If it never gets signaled, it never returns.
        raise NotImplementedError(f"No idea how to correctly model {self.name}")


class Sigpending(Sigemptyset):
    name = "sigpending"

    # int sigpending(sigset_t *set);

    # We don't support signals.
    # If you need pending signals, this will be a problem
    imprecise = True

    # Since we don't support signals, no signals will ever be pending.
    # This is semantically equivalent to sigemptyset()


class Sigprocmask(PthreadSigmask):
    name = "sigprocmask"

    # int sigprocmask(int, const sigset_t *set, sigset_t *oldset);

    # Without threads, this is identical to PthreadSigmask


class Sigqueue(CStdModel):
    name = "sigqueue"

    # int sigqueue(pid_t pid, int sig, const union sigval);
    argument_types = [ArgumentType.INT, ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # This doesn't actually send a signal
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class Sigrelse(CStdModel):
    name = "sigrelse"

    # int sigrelse(int sig);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    # This is part of a historical System V signal handler.
    # Unlike sigaction and sigprocmask,
    # it's not easy to localize across functions.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class Sigset(CStdModel):
    name = "sigset"

    # typedef void (*sighandler_t)(int);
    # sighandler_t sigset(int, sighandler_t handler);
    argument_types = [ArgumentType.INT, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # This is part of a historical System V signal handler.
    # Unlike sigaction and sigprocmask,
    # it's not easy to localize across functions.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return success
        self.set_return_value(emulator, 0)


class Sigsuspend(CStdModel):
    name = "sigsuspend"

    # int sigsuspend(sigset_t *set);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # This one's fun.  If it never gets signaled, it never returns.
        raise NotImplementedError(f"No idea how to correctly model {self.name}")


class Sigtimedwait(CStdModel):
    name = "sigtimedwait"

    # int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timespec);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # This model assumes it always times out,
    # even if no timeout was specified
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # Not really modeled; just return.
        # TODO: This API relies on errno
        self.set_return_value(emulator, -1)


class Sigwait(CStdModel):
    name = "sigwait"

    # int sigwait(const sigset_t *set, int *sig);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # This one's fun.  If it never gets signaled, it never returns.
        raise NotImplementedError(f"No idea how to correctly model {self.name}")


class Sigwaitinfo(CStdModel):
    name = "sigwaitinfo"

    # int sigwaitinfo(const sigset_t *set, siginfo_t *sig);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        # This one's fun.  If it never gets signaled, it never returns.
        raise NotImplementedError(f"No idea how to correctly model {self.name}")


__all__ = [
    "BsdSignal",
    "Kill",
    "Killpg",
    "PthreadKill",
    "PthreadSigmask",
    "Sigaction",
    "Sigaddset",
    "Sigaltstack",
    "Sigdelset",
    "Sigemptyset",
    "Sigfillset",
    "Sighold",
    "Sigignore",
    "Siginterrupt",
    "Sigismember",
    "Sigpause",
    "Sigpending",
    "Sigprocmask",
    "Sigqueue",
    "Sigrelse",
    "Sigset",
    "Sigsuspend",
    "Sigtimedwait",
    "Sigwait",
    "Sigwaitinfo",
]
