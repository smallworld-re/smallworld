import logging
import random
import typing

import claripy

from smallworld.state.models.funcptr import FunctionPointer

from .... import emulators, exceptions
from ...memory.heap import Heap
from ..cstd import ArgumentType, CStdModel
from ..model import RELOCATED_TLS_MODULE
from .utils import _emu_strlen

logger = logging.getLogger("__name__")


class Abort(CStdModel):
    name = "abort"

    # void abort(void);
    argument_types = []
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.EmulationStop("Called abort()")


class Abs(CStdModel):
    name = "abs"

    # int abs(int val);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.INT

    @property
    def sign_mask(self):
        return self._int_sign_mask

    @property
    def inv_mask(self):
        return self._int_inv_mask

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        val = self.get_arg1(emulator)

        assert isinstance(val, int)

        if val & self.sign_mask:
            val = ((val ^ self.inv_mask) + 1) & self.inv_mask

        self.set_return_value(emulator, val)


class LAbs(Abs):
    name = "labs"

    # long labs(long x);
    argument_types = [ArgumentType.LONG]
    return_type = ArgumentType.LONG

    @property
    def sign_mask(self):
        return self._long_sign_mask

    @property
    def inv_mask(self):
        return self._long_inv_mask


class LLAbs(Abs):
    name = "llabs"

    # long long llabs(long long x);
    argument_types = [ArgumentType.LONGLONG]
    return_type = ArgumentType.LONGLONG

    @property
    def sign_mask(self):
        return self._long_long_sign_mask

    @property
    def inv_mask(self):
        return self._long_long_inv_mask


class Atexit(CStdModel):
    name = "atexit"

    # NOTE: In glibc binaries, relocate atexit against __cxa_atexit
    # atexit is a statically-linked helper that calls __cxa_atexit

    # void atexit(void);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # This will not actually result in an exit handler getting registered.
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        self.set_return_value(emulator, 0)


class Atof(CStdModel):
    name = "atof"

    # float atof(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.FLOAT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # TODO: Support other locales for atof
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)
        text = data.decode("utf-8")

        # This is a bit tricky.  Python is much less accepting than C.
        text = text.strip()
        found_dot = False
        for i in range(0, len(text)):
            if text[i].isnumeric():
                continue
            elif text[i] == ".":
                if found_dot:
                    text = text[0:i]
                    break
                else:
                    found_dot = True
            else:
                text = text[0:i]
                break
        if len(text) == 0:
            text = "0"

        self.set_return_value(emulator, float(text))


class Atoi(CStdModel):
    name = "atoi"

    # int atoi(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # TODO: Support other locales for atoi
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        n = _emu_strlen(emulator, ptr)

        data = emulator.read_memory(ptr, n)
        text = data.decode("utf-8").strip()

        for i in range(0, len(text)):
            if not text[i].isnumeric() and text[i] != "-":
                text = text[0:i]
                break

        if len(text) == 0:
            # No valid number
            self.set_return_value(emulator, 0)
            return

        if self.return_type == ArgumentType.INT:
            size_mask = self._int_inv_mask
        elif self.return_type == ArgumentType.LONG:
            size_mask = self._long_inv_mask
        elif self.return_type == ArgumentType.LONGLONG:
            size_mask = self._long_long_inv_mask
        else:
            raise exceptions.ConfigurationError(
                f"Unexpected return type {self.return_type}"
            )

        # TODO: Not entirely sure if this is how truncation will work.
        newval = int(text) & size_mask
        self.set_return_value(emulator, newval)


class Atol(Atoi):
    name = "atol"

    # long atoll(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONG


class Atoll(Atoi):
    name = "atoll"

    # long long atoll(const char *str);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.LONGLONG


class Bsearch(CStdModel):
    name = "bsearch"

    # void *bsearch(const void *key, const void *base,
    #               size_t nitems, size_t size,
    #               int (*compar)(const void *, const void *));
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.POINTER

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        if not self.skip_return:
            # store address to return to after model is done
            self.return_addr = self.get_return_address(emulator)

            # collect args
            self.key_ptr = typing.cast(int, self.get_arg1(emulator))
            self.base_ptr = typing.cast(int, self.get_arg2(emulator))
            self.nmemb = typing.cast(int, self.get_arg3(emulator))
            self.size = typing.cast(int, self.get_arg4(emulator))
            self.compar = typing.cast(int, self.get_arg5(emulator))
            assert isinstance(self.key_ptr, int)
            assert isinstance(self.base_ptr, int)
            assert isinstance(self.nmemb, int)
            assert isinstance(self.size, int)
            assert isinstance(self.compar, int)

            # comparison function pointer
            self.compare_func_ptr = FunctionPointer(
                self.compar,
                [ArgumentType.POINTER, ArgumentType.POINTER],
                ArgumentType.INT,
                self.platform,
            )

            # initialize searching variables and comparison stack frame
            self.low: int = 0
            self.high: int = self.nmemb - 1

            # return back to this model
            self.skip_return = True

        else:
            # read array and last call's return value
            ret = self.compare_func_ptr.get_return_value(emulator)

            # handle comparison result
            if ret == 0:
                self.set_return_value(emulator, self.base_ptr + (self.mid * self.size))
                self.set_return_address(emulator, self.return_addr)
                self.skip_return = False
                return
            elif ret > 0:
                self.low = self.mid + 1
            elif ret < 0:
                self.high = self.mid - 1

            # searched entire array
            if self.low > self.high:
                self.set_return_value(emulator, 0)
                self.set_return_address(emulator, self.return_addr)
                self.skip_return = False
                return

        # call comparison function and return to this model
        self.mid: int = self.low + ((self.high - self.low) // 2)
        self.compare_func_ptr.call(
            emulator,
            [
                self.key_ptr,
                self.base_ptr + (self.mid * self.size),
            ],
            self._address,
        )


class Calloc(CStdModel):
    name = "calloc"

    # void *calloc(size_t amount, size_t size);
    argument_types = [ArgumentType.SIZE_T, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "calloc needs a heap; please assign self.heap"
            )

        amt = self.get_arg1(emulator)
        size = self.get_arg2(emulator)

        assert isinstance(amt, int)
        assert isinstance(size, int)

        total = amt * size
        size_t_max = (1 << (self.platdef.address_size * 8)) - 1
        if total > size_t_max:
            # calloc detects the size_t overflow and returns NULL
            self.set_return_value(emulator, 0)
            return

        data = b"\0" * total

        res = self.heap.allocate_bytes(data, None)
        # This is calloc; zero out the memory
        emulator.write_memory(res, data)

        self.set_return_value(emulator, res)


class Div(CStdModel):
    name = "div"

    # div_t result(int dividend, int divisor);
    argument_types = [ArgumentType.INT, ArgumentType.INT]
    return_type = ArgumentType.VOID

    # div, ldiv, and lldiv basically disobey the ABI.
    #
    # It returns a non-static buffer by stealing
    # stack space from the caller.
    #
    # This would be fine, but different platforms
    # use different mechanisms for the theft.
    #
    # I am not touching that drama.
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.UnsupportedModelError(
            f"{self.name}() has a unique, unsupported calling convention"
        )


class LDiv(Div):
    name = "ldiv"

    # ldiv_t result(long dividend, long divisor);
    argument_types = [ArgumentType.LONG, ArgumentType.LONG]


class LLDiv(Div):
    name = "lldiv"

    # lldiv_t result(long long dividend, long long divisor);
    argument_types = [ArgumentType.LONGLONG, ArgumentType.LONGLONG]


class Exit(CStdModel):
    name = "exit"

    # void exit(int code);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        raise exceptions.EmulationStop("Called exit()")


class Free(CStdModel):
    name = "free"

    # void free(void *ptr);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.VOID

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "malloc needs a heap; please assign self.heap"
            )

        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        self.heap.free(ptr)


class Getenv(CStdModel):
    name = "getenv"

    # char *getenv(char *name);
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    # We don't have a model of envp,
    # so this will always return NULL
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        size = _emu_strlen(emulator, ptr)
        data = emulator.read_memory(ptr, size)
        name = data.decode("utf-8")

        logger.debug(f"getenv({name});")
        self.set_return_value(emulator, 0)


class Malloc(CStdModel):
    name = "malloc"

    # void *malloc(size_t size);
    argument_types = [ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "malloc needs a heap; please assign self.heap"
            )

        size = self.get_arg1(emulator)

        assert isinstance(size, int)

        res = self.heap.allocate_bytes(b"\0" * size, None)

        self.set_return_value(emulator, res)


class TlsGetAddr(CStdModel):
    # void *__tls_get_addr(tls_index *ti);  -- the glibc dynamic-TLS resolver.
    #
    # tls_index is { unsigned long ti_module; unsigned long ti_offset; } and the
    # real resolver returns dtv[ti_module] + ti_offset, i.e. the address of a
    # thread-local *within* that module's TLS block -- ti_offset indexes into the
    # block, it does not name a distinct block.  The harness has no DTV or
    # threads, so we model it with a small fixed pool of per-module arenas in our
    # own zeroed static buffer (NOT the malloc heap): a call returns
    #   arena[module] + offset
    # so ti_offset indexes within the module's arena, exactly like the real
    # resolver, and repeated accesses to the same thread-local see the same
    # storage.  This is bounded by construction -- the module->arena map is
    # capped and offsets are confined to an arena -- so a garbage or
    # loop-varying descriptor can no longer drive the old behaviour (a fresh
    # never-freed 4 KiB block per distinct (module, offset)), which exhausted the
    # shared allocator heap.  Keeping TLS off the malloc heap also stops the two
    # from starving each other.
    name = "__tls_get_addr"
    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.POINTER

    TLS_ARENA_SIZE = 0x1000  # bytes of scratch per module arena
    TLS_MAX_MODULES = 8  # distinct module arenas (extra modules alias in via %)
    #: Where a module's PT_TLS initialization image belongs in the pool. The
    #: relocator reports every module as id 1 (see R_X86_64_DTPMOD64), so the
    #: image seeds that module's arena; without it every thread-local reads
    #: zero rather than its initializer.
    tls_image_offset = TLS_ARENA_SIZE * (RELOCATED_TLS_MODULE % TLS_MAX_MODULES)
    #: A thread-local can only ever be read within its own arena (the model
    #: clamps to one), so that -- not the whole pool -- is the room an image has.
    tls_image_capacity = TLS_ARENA_SIZE
    _TLS_HEADROOM = 0x40  # keep a wide access from a near-arena-end offset in-bounds
    # Reserved once by the library, which sets self.static_buffer_address and maps
    # the (zeroed) region; sized to hold the whole arena pool.
    static_space_required = TLS_ARENA_SIZE * TLS_MAX_MODULES

    def __init__(self, address: int):
        super().__init__(address)
        # Kept for interface compatibility (the library assigns it, like
        # malloc/calloc), but TLS no longer draws from the heap.
        self.heap: typing.Optional[Heap] = None

    @classmethod
    def module_arena_offset(cls, module: int) -> int:
        """Offset within the pool at which ``module``'s arena begins."""
        return cls.TLS_ARENA_SIZE * (module % cls.TLS_MAX_MODULES)

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.static_buffer_address is None:
            raise exceptions.ConfigurationError(
                "__tls_get_addr needs its static buffer; none was reserved"
            )
        ti = self.get_arg1(emulator)
        assert isinstance(ti, int)
        ptr = ArgumentType.POINTER
        module = self.read_integer(ti, ptr, emulator)
        offset = self.read_integer(ti + self.platdef.address_size, ptr, emulator)
        # Map (module, offset) into the bounded arena pool: pick a module arena
        # (garbage/overflow modules alias via %), and index by offset within it,
        # clamped so even a wide access from a near-end offset stays mapped.
        slot = module % self.TLS_MAX_MODULES
        off = min(
            offset % self.TLS_ARENA_SIZE, self.TLS_ARENA_SIZE - self._TLS_HEADROOM
        )
        addr = self.static_buffer_address + slot * self.TLS_ARENA_SIZE + off
        self.set_return_value(emulator, addr)


class TlsDescResolve(CStdModel):
    # The TLS-descriptor resolver, for code built with -mtls-dialect=gnu2.
    #
    # gnu2 replaces the __tls_get_addr call with an indirect call through a
    # two-word descriptor in the GOT: { resolver, argument }. The caller does
    #     lea  x@TLSDESC(%rip), %rax
    #     call *x@TLSCALL(%rax)      # descriptor address in, offset out
    #     mov  %fs:(%rax), ...       # or: mov %fs:0x0,%rdx; add %rdx,%rax
    # so the resolver returns a THREAD-POINTER-RELATIVE offset, not an address
    # -- the difference from TlsGetAddr, which returns the address itself.
    #
    # NOTE: gcc emits BOTH completions above, sometimes in one function. The
    # first adds the thread-pointer register; the second adds the word AT the
    # thread pointer (the glibc TCB self-pointer). They agree only when the
    # harness has set up a TCB, i.e. when the word at [thread_pointer] equals
    # thread_pointer. Nothing in smallworld does that today, so a harness must
    # either leave the thread pointer at 0 (and map a zero word at address 0
    # for the second form) or write a proper self-pointer; otherwise the
    # second form lands the access at arena - thread_pointer.
    #
    # Storage is TlsGetAddr's arena for module 1 -- the module the relocator
    # reports for every thread-local -- indexed by the descriptor's argument
    # (the block offset), so repeated accesses to one thread-local see the same
    # bytes and a garbage argument cannot escape the arena. The descriptor ABI
    # has no module field, which is exactly why the two models can share: both
    # dialects reduce to "block offset within the one module's block", so
    # `gd_x` and `desc_x` naming the same thread-local land on the same bytes
    # whichever dialect each translation unit was built with.
    #
    # The returned offset is tls_arena_address - thread_pointer, so the caller's
    # thread-pointer-relative access lands back on the arena.
    name = "__tlsdesc_resolve"
    # Not a C function: the descriptor ABI passes its argument in a fixed
    # register rather than the usual argument registers, so there is nothing
    # for the generic argument machinery to describe.
    argument_types: typing.List[ArgumentType] = []
    return_type = ArgumentType.POINTER

    # No storage of its own: it shares TlsGetAddr's arena for module 1, which
    # is the module the relocator reports for every thread-local (see
    # R_X86_64_DTPMOD64). gcc picks a TLS dialect per translation unit, so one
    # image can reach the SAME thread-local through both models; with separate
    # pools a write through one is invisible to a read through the other.
    # Sharing also stops every amd64 harness reserving a second 32 KiB pool it
    # may never touch. Assigned by the library, like malloc's heap.
    static_space_required = 0
    _TLS_HEADROOM = 0x40  # keep a wide access from a near-arena-end offset in-bounds

    #: Register holding the descriptor address on entry and the offset on exit.
    descriptor_register: str = ""
    #: Register holding the thread pointer the returned offset is relative to.
    thread_pointer_register: str = ""

    def apply(self, emulator: emulators.Emulator) -> None:
        super().apply(emulator)
        # Install the TCB self-pointer BEFORE any code runs. gcc hoists the
        # `mov %fs:0x0,%rdx` that reads it above the descriptor call -- often
        # to the top of the function -- so a resolver that only writes it
        # during the call writes it after the value has already been read.
        # That read then yields zero and the access lands at
        # `arena - thread_pointer` instead of on the arena.
        try:
            thread_pointer = emulator.read_register(self.thread_pointer_register)
        except Exception:
            return
        if thread_pointer:
            # A harness that maps its own TCB may not have been applied yet --
            # apply order is the caller's, not ours -- so make sure the word
            # exists before writing it. map_memory only fills gaps, so this
            # neither disturbs an already-mapped TCB nor stops one being added
            # later.
            emulator.map_memory(thread_pointer, self.platdef.address_size)
        self._ensure_tcb_self_pointer(emulator, thread_pointer)

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.tls_arena_address is None or self.tls_arena_size <= 0:
            raise exceptions.ConfigurationError(
                "__tlsdesc_resolve needs the shared TLS arena; none was assigned"
            )
        if not self.descriptor_register or not self.thread_pointer_register:
            raise exceptions.ConfigurationError(
                "__tlsdesc_resolve has no descriptor/thread-pointer register "
                "for this platform"
            )
        desc = emulator.read_register(self.descriptor_register)
        argument = self.read_integer(
            desc + self.platdef.address_size, ArgumentType.POINTER, emulator
        )
        off = min(
            argument % self.tls_arena_size,
            max(0, self.tls_arena_size - self._TLS_HEADROOM),
        )
        addr = self.tls_arena_address + off
        try:
            thread_pointer = emulator.read_register(self.thread_pointer_register)
        except exceptions.UnsupportedRegisterError:
            # Some backends (ghidra, triton) do not model segment bases at all.
            # Treating the thread pointer as unset degrades to handing back the
            # arena address itself, which is what happens on every backend when
            # nothing has set one.
            thread_pointer = 0
        self._ensure_tcb_self_pointer(emulator, thread_pointer)
        # Wraps for a thread pointer above the arena, which is the normal
        # variant-II layout: the caller's add wraps back to the same address.
        emulator.write_register(
            self.descriptor_register, (addr - thread_pointer) & self._long_inv_mask
        )

    def _ensure_tcb_self_pointer(
        self, emulator: emulators.Emulator, thread_pointer: int
    ) -> None:
        """Make the word at the thread pointer point at the thread pointer.

        gcc finishes a descriptor call in one of two ways, and emits both --
        sometimes within one function:

            add %fs_base, %rax          # thread-pointer REGISTER
            mov %fs:0x0,%rdx; add %rdx  # the word AT the thread pointer

        Real glibc keeps a TCB whose first word points at itself, which is
        what makes the two agree. Nothing else in the harness sets one up, so
        the second form would otherwise add zero (or whatever happens to be
        there) and send the access somewhere unrelated -- silently, since a
        wrong address is still a valid one. Writing the self-pointer here
        costs one word and makes both forms land on the same storage.

        Best effort: a thread pointer of zero, or one whose page is not
        mapped, leaves it alone rather than failing the access.
        """
        if not thread_pointer:
            return
        size = self.platdef.address_size
        try:
            if self.read_integer(thread_pointer, ArgumentType.POINTER, emulator) == (
                thread_pointer
            ):
                return
            emulator.write_memory(
                thread_pointer,
                thread_pointer.to_bytes(size, self.platdef.byteorder.value),
            )
        except Exception as e:
            logger.debug(f"could not install a TCB self-pointer: {e!r}")


class Mblen(CStdModel):
    name = "mblen"

    # int mblen(char *str, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.INT

    # Alternate encodings not supported
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise exceptions.UnsupportedModelError(f"{self.name} requires locale support")


class Mbstowcs(CStdModel):
    name = "mbstowcs"

    # size_t mbstowcs(schar_t *pwcs, char *str, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.SIZE_T

    # Alternate encodings not supported
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise exceptions.UnsupportedModelError(f"{self.name} requires locale support")


class Mbtowc(CStdModel):
    name = "mbtowc"

    # size_t mbtowc(wchar_t *pwcs, char *str, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.INT

    # Alternate encodings not supported
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise exceptions.UnsupportedModelError(f"{self.name} requires locale support")


class QSort(CStdModel):
    name = "qsort"

    # void qsort(void *arr, size_t amount, size_t size, int (*compare)(const void *, const void *));
    argument_types = [
        ArgumentType.POINTER,
        ArgumentType.SIZE_T,
        ArgumentType.SIZE_T,
        ArgumentType.POINTER,
    ]
    return_type = ArgumentType.VOID
    return_addr = 0

    def model(self, emulator: emulators.Emulator) -> None:
        """This implementation uses Insertion sort as a state machine.
        The model points the emulator at the comparison function and sets the
        return address back to the model until the array has been fully sorted.
        """
        super().model(emulator)

        if not self.skip_return:
            # store address to return to after model is done
            self.return_addr = self.get_return_address(emulator)

            # collect args
            self.base = typing.cast(int, self.get_arg1(emulator))
            self.nmemb = typing.cast(int, self.get_arg2(emulator))
            self.size = typing.cast(int, self.get_arg3(emulator))
            self.compar = typing.cast(int, self.get_arg4(emulator))
            assert isinstance(self.base, int)
            assert isinstance(self.nmemb, int)
            assert isinstance(self.size, int)
            assert isinstance(self.compar, int)

            # comparison function pointer
            self.compare_func_ptr = FunctionPointer(
                self.compar,
                [ArgumentType.POINTER, ArgumentType.POINTER],
                ArgumentType.INT,
                self.platform,
            )

            # initialize sorting variables and comparison stack frame
            self.i = 1
            self.j = self.i
            self.compare_func_ptr.call(
                emulator,
                [
                    self.base + (self.j * self.size),
                    self.base + (self.j - 1) * self.size,
                ],
                self._address,
            )

            # return back to this model
            self.skip_return = True
            return

        if self.skip_return:
            # read array and last call's return value
            elem_addrs = [self.base + i * self.size for i in range(0, self.nmemb)]
            current_array = [
                emulator.read_memory(addr, self.size) for addr in elem_addrs
            ]
            ret = self.compare_func_ptr.get_return_value(emulator)

            # conditionally swap elements and overwrite array
            if ret < 0:
                tmp = current_array[self.j]
                current_array[self.j] = current_array[self.j - 1]
                current_array[self.j - 1] = tmp
                emulator.write_memory(self.base, b"".join(current_array))

            # advance sorting variables
            self.j -= 1
            if self.j <= 0:
                self.i += 1
                self.j = self.i

            # break if we're sorted
            if self.i == self.nmemb:
                self.set_return_address(emulator, self.return_addr)
                self.skip_return = False
                return

            # call comparison function and return to this model
            self.compare_func_ptr.call(
                emulator,
                [
                    self.base + (self.j * self.size),
                    self.base + (self.j - 1) * self.size,
                ],
                self._address,
            )


class Rand(CStdModel):
    name = "rand"

    # int rand(void);
    argument_types = []
    return_type = ArgumentType.INT

    rand = random.Random()

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # TODO: Rand is easy to do simply, harder to do right.
        # If someone is relying on srand/rand to produce a specific sequence,
        # this won't behave correctly.
        val = self.rand.randint(0, 2147483647)
        self.set_return_value(emulator, val)


class Realloc(CStdModel):
    name = "realloc"

    # void *realloc(void *ptr, size_t size);
    argument_types = [ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.POINTER

    def __init__(self, address: int):
        super().__init__(address)
        # Use the same heap model the harness used.
        # NOTE: This will get cloned on a deep copy.
        self.heap: typing.Optional[Heap] = None

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        if self.heap is None:
            raise exceptions.ConfigurationError(
                "realloc needs a heap; please assign self.heap"
            )

        ptr = self.get_arg1(emulator)
        size = self.get_arg2(emulator)

        assert isinstance(ptr, int)
        assert isinstance(size, int)

        logger.warning(f"REALLOC {hex(ptr)}, {size}")

        if ptr == 0:
            res = self.heap.allocate_bytes(b"\0" * size, None)
        elif ptr - self.heap.address not in self.heap:
            raise exceptions.EmulationError(
                f"Attempted to realloc {hex(ptr)}, which was not malloc'd on this heap"
            )
        else:
            oldsize = self.heap[ptr - self.heap.address].get_size()
            data: typing.Union[bytes, claripy.ast.bv.BV]
            try:
                data = emulator.read_memory(ptr, oldsize)
            except exceptions.SymbolicValueError:
                data = emulator.read_memory_symbolic(ptr, oldsize)

            self.heap.free(ptr)

            res = self.heap.allocate_bytes(b"\0" * size, None)
            emulator.write_memory(res, data)

        self.set_return_value(emulator, res)


class Srand(CStdModel):
    name = "srand"

    # void srand(int seed);
    argument_types = [ArgumentType.INT]
    return_type = ArgumentType.VOID

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        seed = self.get_arg1(emulator)
        Rand.rand.seed(a=seed)


class System(CStdModel):
    name = "system"

    argument_types = [ArgumentType.POINTER]
    return_type = ArgumentType.INT

    # This won't actually execute a subprocess
    imprecise = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        ptr = self.get_arg1(emulator)

        assert isinstance(ptr, int)

        size = _emu_strlen(emulator, ptr)
        data = emulator.read_memory(ptr, size)
        cmd = data.decode("utf-8")

        logger.debug(f"system({cmd});")
        self.set_return_value(emulator, 0)


class Wcstombs(CStdModel):
    name = "wctombs"

    # size_t wctombs(char *str, wchar_t *pwcs, size_t n);
    argument_types = [ArgumentType.POINTER, ArgumentType.POINTER, ArgumentType.SIZE_T]
    return_type = ArgumentType.SIZE_T

    # Alternate encodings not supported
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise exceptions.UnsupportedModelError(f"{self.name} requires locale support")


class Wctomb(CStdModel):
    name = "wctomb"

    # int wctomb(char *str, wchar_t wchar);
    argument_types = [ArgumentType.POINTER, ArgumentType.UINT]
    return_type = ArgumentType.INT

    # Alternate encodings not supported
    unsupported = True

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)
        # Depends the locale.
        raise exceptions.UnsupportedModelError(f"{self.name} requires locale support")


__all__ = [
    "Abs",
    "LAbs",
    "LLAbs",
    "Abort",
    "Atexit",
    "Atof",
    "Atoi",
    "Atol",
    "Atoll",
    "Bsearch",
    "Calloc",
    "Div",
    "LDiv",
    "LLDiv",
    "Exit",
    "Free",
    "Getenv",
    "Malloc",
    "TlsGetAddr",
    "TlsDescResolve",
    "Mblen",
    "Mbstowcs",
    "Mbtowc",
    "QSort",
    "Rand",
    "Realloc",
    "Srand",
    "System",
    "Wcstombs",
    "Wctomb",
]
