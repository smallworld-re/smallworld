import abc
import typing

from .. import emulators, platform, utils


class Stateful(metaclass=abc.ABCMeta):
    """System state that can be applied to/loaded from an emulator."""

    @abc.abstractmethod
    def extract(self, emulator: emulators.Emulator) -> None:
        """Load state from an emulator.

        Arguments:
            emulator: The emulator from which to load
        """

    @abc.abstractmethod
    def apply(self, emulator: emulators.Emulator) -> None:
        """Apply state to an emulator.

        Arguments:
            emulator: The emulator to which state should applied.
        """


class Value(Stateful):
    """An individual state value."""

    _content: typing.Optional[typing.Any] = None
    _type: typing.Optional[typing.Any] = None
    _label: typing.Optional[str] = None

    @abc.abstractmethod
    def get_size(self) -> int:
        """Get the size of this object.

        Returns:
            The size this object should occupy in memory.
        """

        return 0

    def get_content(self) -> typing.Optional[typing.Any]:
        """Get the content of this object.

        Returns:
            The content of this object.
        """

        return self._content

    def set_content(self, content: typing.Optional[typing.Any]) -> None:
        """Set the content of this object.

        Arguments:
            content: The content value to set.
        """

        self._content = content

    def get_type(self) -> typing.Optional[typing.Any]:
        """Get the type of this object.

        Returns:
            The type of this object.
        """

        return self._type

    def set_type(self, type: typing.Optional[typing.Any]) -> None:
        """Set the type of this object.

        Arguments:
            type: The type value to set.
        """

        self._type = type

    def get_label(self) -> typing.Optional[str]:
        """Get the label of this object.

        Returns:
            The label of this object.
        """

        return self._label

    def set_label(self, label: typing.Optional[str]) -> None:
        """Set the label of this object.

        Arguments:
            type: The label value to set.
        """

        self._label = label

    def get(self) -> typing.Optional[typing.Any]:
        """A helper to get the content of this object.

        Returns:
            The content of this object.
        """

        return self.get_content()

    def set(self, content: typing.Optional[typing.Any]) -> None:
        """A helper to set the content of this object.

        Arguments:
            content: The content value to set.
        """

        self.set_content(content)

    @abc.abstractmethod
    def to_bytes(self, byteorder: platform.Byteorder) -> bytes:
        """Convert this object into a byte string.

        Arguments:
            byteorder: Byteorder for conversion to raw bytes.

        Returns:
            Bytes for this object with the given byteorder.
        """

        return b""

    @classmethod
    def from_ctypes(cls, value: typing.Any):
        """Load from an existing ctypes object."""

        raise NotImplementedError("loading from ctypes is not yet implemented")


class Register(Value):
    """An individual register.

    Arguments:
        name: The canonical name of the register.
        size: The size (in bytes) of the register.
    """

    _content: typing.Optional[int] = None
    _type = None
    _label = None

    def __init__(self, name: str, size: int = 4):
        super().__init__()

        self.name: str = name
        """Canonical name."""

        self.size = size
        """Register size in bytes."""

    def get_size(self) -> int:
        return self.size

    def extract(self, emulator: emulators.Emulator) -> None:
        self.set_content(emulator.read_register_content(self.name))
        self.set_type(emulator.read_register_type(self.name))
        self.set_label(emulator.read_register_label(self.name))

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_register_content(self.name, self.get_content())
        emulator.write_register_type(self.name, self.get_type())
        emulator.write_register_label(self.name, self.get_label())

    def to_bytes(self, byteorder: platform.Byteorder) -> bytes:
        value = self.get_content()

        if byteorder == platform.Byteorder.LITTLE:
            return value.to_bytes(self.size, byteorder="little")
        elif byteorder == platform.Byteorder.BIG:
            return value.to_bytes(self.size, byteorder="big")
        else:
            raise ValueError(f"unsupported byteorder {byteorder}")


class RegisterAlias(Register):
    """An alias to a partial register.

    Arguments:
        name: The cannonical name of the register.
        reference: A register which this alias references.
        size: The size (in bytes) of the register.
        offset: The offset from the start of the register that this alias
            references.

    """

    def __init__(self, name: str, reference: Register, size: int = 4, offset: int = 0):
        super().__init__(name, size)

        self.reference: Register = reference
        """The register referenced by this alias."""

        self.offset: int = offset
        """'The offset into the referenced register."""

    @property
    def mask(self) -> int:
        mask = (1 << self.size * 8) - 1
        mask <<= self.offset * 8

        return mask

    def extract(self, emulator: emulators.Emulator) -> None:
        self.reference.extract(emulator)

        value = self.reference.get_content() & self.mask
        value >>= self.offset * 8

        self.set_content(value)
        self.set_type(self.reference.get_type())
        self.set_label(self.reference.get_label())

    def apply(self, emulator: emulators.Emulator) -> None:
        value = self.reference.get_content()
        value = (value & ~self.mask) + self.get_content()

        self.reference.set_content(value)
        self.reference.set_type(self.get_type())
        self.reference.set_label(self.get_label())


class Memory(Stateful, dict):
    """A memory region.

    This dictionary maps integer offsets from the base ``address`` to ``Value``
    classes.
    """

    def __init__(self, address: int, size: int, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.address: int = address
        """The start address of this memory region."""

        self.size: int = size
        """The size address of this memory region."""

    def to_bytes(self, byteorder: platform.Byteorder) -> bytes:
        """Convert this memory region into a byte string.

        Missing/undefined space will be filled with zeros.

        Arguments:
            byteorder: Byteorder for conversion to raw bytes.

        Returns:
            Bytes for this object with the given byteorder.
        """

        result = b"\x00" * self.size
        for offset, value in self.items():
            data = value.get_content()
            result = (
                result[:offset]
                + data.to_bytes(byteorder=byteorder)
                + result[offset + value.size :]
            )

        return result

    def get_allocated_size(self) -> int:
        """Gets the allocated size of this memory region.

        Returns:
            The allocated size of this memory region.
        """

        return sum([v.get_size() for v in self.values()])

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_memory(
            self.address, self.to_bytes(byteorder=emulator.platform.byteorder)
        )

    def extract(self, emulator: emulators.Emulator) -> None:
        raise NotImplementedError("extracting memory not yet implemented")


class Code(Memory):
    pass


class StatefulSet(Stateful, set):
    def extract(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            stateful.extract(emulator)

    def apply(self, emulator: emulators.Emulator) -> None:
        for stateful in self:
            stateful.apply(emulator)


class CPU(StatefulSet):
    @classmethod
    @abc.abstractmethod
    def get_platform(cls) -> platform.Platform:
        pass

    @classmethod
    def for_platform(cls, platform: platform.Platform):
        try:
            return utils.find_subclass(
                cls,
                lambda x: x.get_platform().architecture == platform.architecture
                and x.get_platform().byteorder == platform.byteorder,
            )
        except ValueError:
            raise ValueError(
                f"No CPU model for {platform.architecture}:{platform.byteorder}"
            )

    @abc.abstractmethod
    def get_general_purpose_registers(self) -> typing.List[str]:
        pass

    def __repr__(self) -> str:
        p = self.get_platform()
        return f"{p.architecture} - {p.byteorder}"


class Machine(StatefulSet):
    pass


class i386CPUState(CPU):
    """i386 CPU state model."""

    _GENERAL_PURPOSE_REGS = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.X86_32, platform.Byteorder.LITTLE
        )

    def __init__(self):
        self.eax = Register("eax")
        self.ax = RegisterAlias("ax", self.eax, size=2)
        self.al = RegisterAlias("al", self.eax, size=1)
        self.ah = RegisterAlias("ah", self.eax, size=1, offset=1)

        self.ebx = Register("ebx")
        self.bx = RegisterAlias("bx", self.ebx, size=2)
        self.bl = RegisterAlias("bl", self.ebx, size=1)
        self.bh = RegisterAlias("bh", self.ebx, size=1, offset=1)

        self.ecx = Register("ecx")
        self.cx = RegisterAlias("cx", self.ecx, size=2)
        self.cl = RegisterAlias("cl", self.ecx, size=1)
        self.ch = RegisterAlias("ch", self.ecx, size=1, offset=1)

        self.edx = Register("edx")
        self.dx = RegisterAlias("dx", self.edx, size=2)
        self.dl = RegisterAlias("dl", self.edx, size=1)
        self.dh = RegisterAlias("dh", self.edx, size=1, offset=1)

        self.esi = Register("esi")
        self.si = RegisterAlias("si", self.esi, size=2)
        self.sil = RegisterAlias("sil", self.esi, size=1)

        self.edi = Register("edi")
        self.di = RegisterAlias("di", self.edi, size=2)
        self.dil = RegisterAlias("dil", self.edi, size=1)

        self.ebp = Register("ebp")
        self.bp = RegisterAlias("bp", self.ebp, size=2)
        self.bpl = RegisterAlias("bpl", self.ebp, size=1)

        self.esp = Register("esp")
        self.sp = RegisterAlias("sp", self.esp, size=2)
        self.spl = RegisterAlias("spl", self.esp, size=1)

        self.eip = Register("eip")
        self.ip = RegisterAlias("ip", self.eip, size=2)

        self.cs = Register("cs")
        self.ds = Register("ds")
        self.es = Register("es")
        self.fs = Register("fs")
        self.gs = Register("gs")

        self.eflags = Register("eflags")
        self.flags = RegisterAlias("flags", self.eflags, size=2)

        self.cr0 = Register("cr0")
        self.cr1 = Register("cr1")
        self.cr2 = Register("cr2")
        self.cr3 = Register("cr3")
        self.cr4 = Register("cr4")


class AMD64CPUState(i386CPUState):
    """AMD64 CPU state model."""

    _GENERAL_PURPOSE_REGS = [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rdi",
        "rsi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ]

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.X86_64, platform.Byteorder.LITTLE
        )

    def __init__(self):
        self.rax = Register("rax", size=8)
        self.eax = RegisterAlias("eax", self.rax, size=4)
        self.ax = RegisterAlias("ax", self.rax, size=2)
        self.al = RegisterAlias("al", self.rax, size=1)
        self.ah = RegisterAlias("ah", self.rax, size=1, offset=1)

        self.rbx = Register("rbx", size=8)
        self.ebx = RegisterAlias("ebx", self.rbx, size=4)
        self.bx = RegisterAlias("bx", self.rbx, size=2)
        self.bl = RegisterAlias("bl", self.rbx, size=1)
        self.bh = RegisterAlias("bh", self.rbx, size=1, offset=1)

        self.rcx = Register("rcx", size=8)
        self.ecx = RegisterAlias("ecx", self.rcx, size=4)
        self.cx = RegisterAlias("cx", self.rcx, size=2)
        self.cl = RegisterAlias("cl", self.rcx, size=1)
        self.ch = RegisterAlias("ch", self.rcx, size=1, offset=1)

        self.rdx = Register("rdx", size=8)
        self.edx = RegisterAlias("edx", self.rdx, size=4)
        self.dx = RegisterAlias("dx", self.rdx, size=2)
        self.dl = RegisterAlias("dl", self.rdx, size=1)
        self.dh = RegisterAlias("dh", self.rdx, size=1, offset=1)

        self.r8 = Register("r8", size=8)
        self.r8d = RegisterAlias("r8d", self.r8, size=4)
        self.r8w = RegisterAlias("r8w", self.r8, size=2)
        self.r8b = RegisterAlias("r8b", self.r8, size=1)

        self.r9 = Register("r9", size=8)
        self.r9d = RegisterAlias("r9d", self.r9, size=4)
        self.r9w = RegisterAlias("r9w", self.r9, size=2)
        self.r9b = RegisterAlias("r9b", self.r9, size=1)

        self.r10 = Register("r10", size=8)
        self.r10d = RegisterAlias("r10d", self.r10, size=4)
        self.r10w = RegisterAlias("r10w", self.r10, size=2)
        self.r10b = RegisterAlias("r10b", self.r10, size=1)

        self.r11 = Register("r11", size=8)
        self.r11d = RegisterAlias("r11d", self.r11, size=4)
        self.r11w = RegisterAlias("r11w", self.r11, size=2)
        self.r11b = RegisterAlias("r11b", self.r11, size=1)

        self.r12 = Register("r12", size=8)
        self.r12d = RegisterAlias("r12d", self.r12, size=4)
        self.r12w = RegisterAlias("r12w", self.r12, size=2)
        self.r12b = RegisterAlias("r12b", self.r12, size=1)

        self.r13 = Register("r13", size=8)
        self.r13d = RegisterAlias("r13d", self.r13, size=4)
        self.r13w = RegisterAlias("r13w", self.r13, size=2)
        self.r13b = RegisterAlias("r13b", self.r13, size=1)

        self.r14 = Register("r14", size=8)
        self.r14d = RegisterAlias("r14d", self.r14, size=4)
        self.r14w = RegisterAlias("r14w", self.r14, size=2)
        self.r14b = RegisterAlias("r14b", self.r14, size=1)

        self.r15 = Register("r15", size=8)
        self.r15d = RegisterAlias("r15d", self.r15, size=4)
        self.r15w = RegisterAlias("r15w", self.r15, size=2)
        self.r15b = RegisterAlias("r15b", self.r15, size=1)

        self.rsi = Register("rsi", size=8)
        self.esi = RegisterAlias("esi", self.rsi, size=4)
        self.si = RegisterAlias("si", self.rsi, size=2)
        self.sil = RegisterAlias("sil", self.rsi, size=1)

        self.rdi = Register("rdi", size=8)
        self.edi = RegisterAlias("edi", self.rdi, size=4)
        self.di = RegisterAlias("di", self.rdi, size=2)
        self.dil = RegisterAlias("dil", self.rdi, size=1)

        self.rbp = Register("rbp", size=8)
        self.ebp = RegisterAlias("ebp", self.rbp, size=4)
        self.bp = RegisterAlias("bp", self.rbp, size=2)
        self.bpl = RegisterAlias("bpl", self.rbp, size=1)

        self.rsp = Register("rsp", size=8)
        self.esp = RegisterAlias("esp", self.rsp, size=4)
        self.sp = RegisterAlias("sp", self.rsp, size=2)
        self.spl = RegisterAlias("spl", self.rsp, size=1)

        self.rip = Register("rip", size=8)
        self.eip = RegisterAlias("eip", self.rip, size=4)
        self.ip = RegisterAlias("ip", self.rip, size=2)

        self.cs = Register("cs", size=8)
        self.ds = Register("ds", size=8)
        self.es = Register("es", size=8)
        self.fs = Register("fs", size=8)
        self.gs = Register("gs", size=8)

        self.rflags = Register("rflags", size=8)
        self.eflags = RegisterAlias("eflags", self.rflags, size=4)
        self.flags = RegisterAlias("flags", self.rflags, size=2)

        self.cr0 = Register("cr0", size=8)
        self.cr1 = Register("cr1", size=8)
        self.cr2 = Register("cr2", size=8)
        self.cr3 = Register("cr3", size=8)
        self.cr4 = Register("cr4", size=8)


class AArch64CPUState(CPU):
    """Auto-generated CPU state for aarch64:v8a:little

    Generated from Pcode language AARCH64:LE:64:v8A,
    and Unicorn package unicorn.arm64_const
    """

    # Special registers:
    # x29: frame pointer
    # x30: link register
    # x31: stack pointer or zero, depending on instruction
    _GENERAL_PURPOSE_REGS = [f"x{i}" for i in range(0, 29)]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.AARCH64, platform.Byteorder.LITTLE
        )

    def __init__(self):
        # *** General Purpose Registers ***
        self.x0 = Register("x0", size=8)
        self.w0 = RegisterAlias("w0", self.x0, size=4, offset=0)
        self.x1 = Register("x1", size=8)
        self.w1 = RegisterAlias("w1", self.x1, size=4, offset=0)
        self.x2 = Register("x2", size=8)
        self.w2 = RegisterAlias("w2", self.x2, size=4, offset=0)
        self.x3 = Register("x3", size=8)
        self.w3 = RegisterAlias("w3", self.x3, size=4, offset=0)
        self.x4 = Register("x4", size=8)
        self.w4 = RegisterAlias("w4", self.x4, size=4, offset=0)
        self.x5 = Register("x5", size=8)
        self.w5 = RegisterAlias("w5", self.x5, size=4, offset=0)
        self.x6 = Register("x6", size=8)
        self.w6 = RegisterAlias("w6", self.x6, size=4, offset=0)
        self.x7 = Register("x7", size=8)
        self.w7 = RegisterAlias("w7", self.x7, size=4, offset=0)
        self.x8 = Register("x8", size=8)
        self.w8 = RegisterAlias("w8", self.x8, size=4, offset=0)
        self.x9 = Register("x9", size=8)
        self.w9 = RegisterAlias("w9", self.x9, size=4, offset=0)
        self.x10 = Register("x10", size=8)
        self.w10 = RegisterAlias("w10", self.x10, size=4, offset=0)
        self.x11 = Register("x11", size=8)
        self.w11 = RegisterAlias("w11", self.x11, size=4, offset=0)
        self.x12 = Register("x12", size=8)
        self.w12 = RegisterAlias("w12", self.x12, size=4, offset=0)
        self.x13 = Register("x13", size=8)
        self.w13 = RegisterAlias("w13", self.x13, size=4, offset=0)
        self.x14 = Register("x14", size=8)
        self.w14 = RegisterAlias("w14", self.x14, size=4, offset=0)
        self.x15 = Register("x15", size=8)
        self.w15 = RegisterAlias("w15", self.x15, size=4, offset=0)
        self.x16 = Register("x16", size=8)
        self.w16 = RegisterAlias("w16", self.x16, size=4, offset=0)
        self.x17 = Register("x17", size=8)
        self.w17 = RegisterAlias("w17", self.x17, size=4, offset=0)
        self.x18 = Register("x18", size=8)
        self.w18 = RegisterAlias("w18", self.x18, size=4, offset=0)
        self.x19 = Register("x19", size=8)
        self.w19 = RegisterAlias("w19", self.x19, size=4, offset=0)
        self.x20 = Register("x20", size=8)
        self.w20 = RegisterAlias("w20", self.x20, size=4, offset=0)
        self.x21 = Register("x21", size=8)
        self.w21 = RegisterAlias("w21", self.x21, size=4, offset=0)
        self.x22 = Register("x22", size=8)
        self.w22 = RegisterAlias("w22", self.x22, size=4, offset=0)
        self.x23 = Register("x23", size=8)
        self.w23 = RegisterAlias("w23", self.x23, size=4, offset=0)
        self.x24 = Register("x24", size=8)
        self.w24 = RegisterAlias("w24", self.x24, size=4, offset=0)
        self.x25 = Register("x25", size=8)
        self.w25 = RegisterAlias("w25", self.x25, size=4, offset=0)
        self.x26 = Register("x26", size=8)
        self.w26 = RegisterAlias("w26", self.x26, size=4, offset=0)
        self.x27 = Register("x27", size=8)
        self.w27 = RegisterAlias("w27", self.x27, size=4, offset=0)
        self.x28 = Register("x28", size=8)
        self.w28 = RegisterAlias("w28", self.x28, size=4, offset=0)
        self.x29 = Register("x29", size=8)
        self.w29 = RegisterAlias("w29", self.x29, size=4, offset=0)
        self.x30 = Register("x30", size=8)
        self.w30 = RegisterAlias("w30", self.x30, size=4, offset=0)

        # *** Special Registers ***
        # Program Counter
        self.pc = Register("pc", size=8)
        # Stack Pointer
        self.sp = Register("sp", size=8)
        self.wsp = RegisterAlias("wsp", self.sp, size=4, offset=0)
        # fp: Frame pointer; alias for x29
        self.fp = RegisterAlias("fp", self.x29, size=8, offset=0)
        # lr: Link register; alias for x30
        self.lr = RegisterAlias("lr", self.x30, size=8, offset=0)
        # Zero Register
        self.xzr = Register("xzr", size=8)
        self.wzr = RegisterAlias("wzr", self.xzr, size=4, offset=0)
        # sp_elX: Banked stack pointers for exception handlers
        self.sp_el0 = Register("sp_el0", size=8)
        self.sp_el1 = Register("sp_el1", size=8)
        self.sp_el2 = Register("sp_el2", size=8)
        self.sp_el3 = Register("sp_el3", size=8)

        # *** System Registers ***
        # NOTE: Here, the name indicates the lowest EL that can access the register.
        # NOTE: The Unicorn model is missing a boatload of other system control registers.

        # Condition code register
        self.fpcr = Register("fpcr", size=8)
        # Floating Point Status Register
        self.fpsr = Register("fpsr", size=8)
        # elr_elX: Banked Exception Link Registers for exception handlers.
        # TODO: Unicorn lists an "elr_el0", but the AArch64 docs don't...
        self.elr_el1 = Register("elr_el1", size=8)
        self.elr_el2 = Register("elr_el2", size=8)
        self.elr_el3 = Register("elr_el3", size=8)
        # esr_elX: Banked Exception Syndrome Registers for exception handlers.
        # TODO: Unicorn lists an "esr_el0", but the AArch64 docs don't...
        self.esr_el1 = Register("esr_el1", size=8)
        self.esr_el2 = Register("esr_el2", size=8)
        self.esr_el3 = Register("esr_el3", size=8)
        # far_elX: Banked Fault Address Registers for exception handlers.
        # TODO: Unicorn lists a "far_el0", but the AArch64 docs don't...
        self.far_el1 = Register("far_el1", size=8)
        self.far_el2 = Register("far_el2", size=8)
        self.far_el3 = Register("far_el3", size=8)
        # vbar_elX: Banked Vector Base Address Registers for exception handlers
        self.vbar_el1 = Register("vbar_el1", size=8)
        # NOTE: vbar_el0 and vbar_el1 are aliases for each other.
        # The Sleigh model only recognizes vbar_el1,
        # so it needs to be the "real" copy.
        self.vbar_el0 = RegisterAlias("vbar_el0", self.vbar_el1, size=8, offset=0)
        self.vbar_el2 = Register("vbar_el2", size=8)
        self.vbar_el3 = Register("vbar_el3", size=8)
        # Coprocessor Access Control Register
        self.cpacr_el1 = Register("cpacr_el1", size=8)
        # Memory Attribute Indirection Register
        # NOTE: There should be four of these.
        self.mair_el1 = Register("mair_el1", size=8)
        # Physical Address Register
        self.par_el1 = Register("par_el1", size=8)
        # Translation Table Zero Base Register
        self.ttbr0_el1 = Register("ttbr0_el1", size=8)
        # Translation Table One Base Register
        self.ttbr1_el1 = Register("ttbr1_el1", size=8)
        # Thread ID Register
        # NOTE: There should be four of these.
        self.tpidr_el0 = Register("tpidr_el0", size=8)
        self.tpidr_el1 = Register("tpidr_el1", size=8)
        # Userspace-visible Thread ID register
        self.tpidrro_el0 = Register("tpidrro_el0", size=8)

        # Scalar floating point registers
        self.q0 = Register("q0", size=16)
        self.d0 = RegisterAlias("d0", self.q0, size=8, offset=0)
        self.s0 = RegisterAlias("s0", self.q0, size=4, offset=0)
        self.h0 = RegisterAlias("h0", self.q0, size=2, offset=0)
        self.b0 = RegisterAlias("b0", self.q0, size=1, offset=0)
        self.q1 = Register("q1", size=16)
        self.d1 = RegisterAlias("d1", self.q1, size=8, offset=0)
        self.s1 = RegisterAlias("s1", self.q1, size=4, offset=0)
        self.h1 = RegisterAlias("h1", self.q1, size=2, offset=0)
        self.b1 = RegisterAlias("b1", self.q1, size=1, offset=0)
        self.q2 = Register("q2", size=16)
        self.d2 = RegisterAlias("d2", self.q2, size=8, offset=0)
        self.s2 = RegisterAlias("s2", self.q2, size=4, offset=0)
        self.h2 = RegisterAlias("h2", self.q2, size=2, offset=0)
        self.b2 = RegisterAlias("b2", self.q2, size=1, offset=0)
        self.q3 = Register("q3", size=16)
        self.d3 = RegisterAlias("d3", self.q3, size=8, offset=0)
        self.s3 = RegisterAlias("s3", self.q3, size=4, offset=0)
        self.h3 = RegisterAlias("h3", self.q3, size=2, offset=0)
        self.b3 = RegisterAlias("b3", self.q3, size=1, offset=0)
        self.q4 = Register("q4", size=16)
        self.d4 = RegisterAlias("d4", self.q4, size=8, offset=0)
        self.s4 = RegisterAlias("s4", self.q4, size=4, offset=0)
        self.h4 = RegisterAlias("h4", self.q4, size=2, offset=0)
        self.b4 = RegisterAlias("b4", self.q4, size=1, offset=0)
        self.q5 = Register("q5", size=16)
        self.d5 = RegisterAlias("d5", self.q5, size=8, offset=0)
        self.s5 = RegisterAlias("s5", self.q5, size=4, offset=0)
        self.h5 = RegisterAlias("h5", self.q5, size=2, offset=0)
        self.b5 = RegisterAlias("b5", self.q5, size=1, offset=0)
        self.q6 = Register("q6", size=16)
        self.d6 = RegisterAlias("d6", self.q6, size=8, offset=0)
        self.s6 = RegisterAlias("s6", self.q6, size=4, offset=0)
        self.h6 = RegisterAlias("h6", self.q6, size=2, offset=0)
        self.b6 = RegisterAlias("b6", self.q6, size=1, offset=0)
        self.q7 = Register("q7", size=16)
        self.d7 = RegisterAlias("d7", self.q7, size=8, offset=0)
        self.s7 = RegisterAlias("s7", self.q7, size=4, offset=0)
        self.h7 = RegisterAlias("h7", self.q7, size=2, offset=0)
        self.b7 = RegisterAlias("b7", self.q7, size=1, offset=0)
        self.q8 = Register("q8", size=16)
        self.d8 = RegisterAlias("d8", self.q8, size=8, offset=0)
        self.s8 = RegisterAlias("s8", self.q8, size=4, offset=0)
        self.h8 = RegisterAlias("h8", self.q8, size=2, offset=0)
        self.b8 = RegisterAlias("b8", self.q8, size=1, offset=0)
        self.q9 = Register("q9", size=16)
        self.d9 = RegisterAlias("d9", self.q9, size=8, offset=0)
        self.s9 = RegisterAlias("s9", self.q9, size=4, offset=0)
        self.h9 = RegisterAlias("h9", self.q9, size=2, offset=0)
        self.b9 = RegisterAlias("b9", self.q9, size=1, offset=0)
        self.q10 = Register("q10", size=16)
        self.d10 = RegisterAlias("d10", self.q10, size=8, offset=0)
        self.s10 = RegisterAlias("s10", self.q10, size=4, offset=0)
        self.h10 = RegisterAlias("h10", self.q10, size=2, offset=0)
        self.b10 = RegisterAlias("b10", self.q10, size=1, offset=0)
        self.q11 = Register("q11", size=16)
        self.d11 = RegisterAlias("d11", self.q11, size=8, offset=0)
        self.s11 = RegisterAlias("s11", self.q11, size=4, offset=0)
        self.h11 = RegisterAlias("h11", self.q11, size=2, offset=0)
        self.b11 = RegisterAlias("b11", self.q11, size=1, offset=0)
        self.q12 = Register("q12", size=16)
        self.d12 = RegisterAlias("d12", self.q12, size=8, offset=0)
        self.s12 = RegisterAlias("s12", self.q12, size=4, offset=0)
        self.h12 = RegisterAlias("h12", self.q12, size=2, offset=0)
        self.b12 = RegisterAlias("b12", self.q12, size=1, offset=0)
        self.q13 = Register("q13", size=16)
        self.d13 = RegisterAlias("d13", self.q13, size=8, offset=0)
        self.s13 = RegisterAlias("s13", self.q13, size=4, offset=0)
        self.h13 = RegisterAlias("h13", self.q13, size=2, offset=0)
        self.b13 = RegisterAlias("b13", self.q13, size=1, offset=0)
        self.q14 = Register("q14", size=16)
        self.d14 = RegisterAlias("d14", self.q14, size=8, offset=0)
        self.s14 = RegisterAlias("s14", self.q14, size=4, offset=0)
        self.h14 = RegisterAlias("h14", self.q14, size=2, offset=0)
        self.b14 = RegisterAlias("b14", self.q14, size=1, offset=0)
        self.q15 = Register("q15", size=16)
        self.d15 = RegisterAlias("d15", self.q15, size=8, offset=0)
        self.s15 = RegisterAlias("s15", self.q15, size=4, offset=0)
        self.h15 = RegisterAlias("h15", self.q15, size=2, offset=0)
        self.b15 = RegisterAlias("b15", self.q15, size=1, offset=0)
        self.q16 = Register("q16", size=16)
        self.d16 = RegisterAlias("d16", self.q16, size=8, offset=0)
        self.s16 = RegisterAlias("s16", self.q16, size=4, offset=0)
        self.h16 = RegisterAlias("h16", self.q16, size=2, offset=0)
        self.b16 = RegisterAlias("b16", self.q16, size=1, offset=0)
        self.q17 = Register("q17", size=16)
        self.d17 = RegisterAlias("d17", self.q17, size=8, offset=0)
        self.s17 = RegisterAlias("s17", self.q17, size=4, offset=0)
        self.h17 = RegisterAlias("h17", self.q17, size=2, offset=0)
        self.b17 = RegisterAlias("b17", self.q17, size=1, offset=0)
        self.q18 = Register("q18", size=16)
        self.d18 = RegisterAlias("d18", self.q18, size=8, offset=0)
        self.s18 = RegisterAlias("s18", self.q18, size=4, offset=0)
        self.h18 = RegisterAlias("h18", self.q18, size=2, offset=0)
        self.b18 = RegisterAlias("b18", self.q18, size=1, offset=0)
        self.q19 = Register("q19", size=16)
        self.d19 = RegisterAlias("d19", self.q19, size=8, offset=0)
        self.s19 = RegisterAlias("s19", self.q19, size=4, offset=0)
        self.h19 = RegisterAlias("h19", self.q19, size=2, offset=0)
        self.b19 = RegisterAlias("b19", self.q19, size=1, offset=0)
        self.q20 = Register("q20", size=16)
        self.d20 = RegisterAlias("d20", self.q20, size=8, offset=0)
        self.s20 = RegisterAlias("s20", self.q20, size=4, offset=0)
        self.h20 = RegisterAlias("h20", self.q20, size=2, offset=0)
        self.b20 = RegisterAlias("b20", self.q20, size=1, offset=0)
        self.q21 = Register("q21", size=16)
        self.d21 = RegisterAlias("d21", self.q21, size=8, offset=0)
        self.s21 = RegisterAlias("s21", self.q21, size=4, offset=0)
        self.h21 = RegisterAlias("h21", self.q21, size=2, offset=0)
        self.b21 = RegisterAlias("b21", self.q21, size=1, offset=0)
        self.q22 = Register("q22", size=16)
        self.d22 = RegisterAlias("d22", self.q22, size=8, offset=0)
        self.s22 = RegisterAlias("s22", self.q22, size=4, offset=0)
        self.h22 = RegisterAlias("h22", self.q22, size=2, offset=0)
        self.b22 = RegisterAlias("b22", self.q22, size=1, offset=0)
        self.q23 = Register("q23", size=16)
        self.d23 = RegisterAlias("d23", self.q23, size=8, offset=0)
        self.s23 = RegisterAlias("s23", self.q23, size=4, offset=0)
        self.h23 = RegisterAlias("h23", self.q23, size=2, offset=0)
        self.b23 = RegisterAlias("b23", self.q23, size=1, offset=0)
        self.q24 = Register("q24", size=16)
        self.d24 = RegisterAlias("d24", self.q24, size=8, offset=0)
        self.s24 = RegisterAlias("s24", self.q24, size=4, offset=0)
        self.h24 = RegisterAlias("h24", self.q24, size=2, offset=0)
        self.b24 = RegisterAlias("b24", self.q24, size=1, offset=0)
        self.q25 = Register("q25", size=16)
        self.d25 = RegisterAlias("d25", self.q25, size=8, offset=0)
        self.s25 = RegisterAlias("s25", self.q25, size=4, offset=0)
        self.h25 = RegisterAlias("h25", self.q25, size=2, offset=0)
        self.b25 = RegisterAlias("b25", self.q25, size=1, offset=0)
        self.q26 = Register("q26", size=16)
        self.d26 = RegisterAlias("d26", self.q26, size=8, offset=0)
        self.s26 = RegisterAlias("s26", self.q26, size=4, offset=0)
        self.h26 = RegisterAlias("h26", self.q26, size=2, offset=0)
        self.b26 = RegisterAlias("b26", self.q26, size=1, offset=0)
        self.q27 = Register("q27", size=16)
        self.d27 = RegisterAlias("d27", self.q27, size=8, offset=0)
        self.s27 = RegisterAlias("s27", self.q27, size=4, offset=0)
        self.h27 = RegisterAlias("h27", self.q27, size=2, offset=0)
        self.b27 = RegisterAlias("b27", self.q27, size=1, offset=0)
        self.q28 = Register("q28", size=16)
        self.d28 = RegisterAlias("d28", self.q28, size=8, offset=0)
        self.s28 = RegisterAlias("s28", self.q28, size=4, offset=0)
        self.h28 = RegisterAlias("h28", self.q28, size=2, offset=0)
        self.b28 = RegisterAlias("b28", self.q28, size=1, offset=0)
        self.q29 = Register("q29", size=16)
        self.d29 = RegisterAlias("d29", self.q29, size=8, offset=0)
        self.s29 = RegisterAlias("s29", self.q29, size=4, offset=0)
        self.h29 = RegisterAlias("h29", self.q29, size=2, offset=0)
        self.b29 = RegisterAlias("b29", self.q29, size=1, offset=0)
        self.q30 = Register("q30", size=16)
        self.d30 = RegisterAlias("d30", self.q30, size=8, offset=0)
        self.s30 = RegisterAlias("s30", self.q30, size=4, offset=0)
        self.h30 = RegisterAlias("h30", self.q30, size=2, offset=0)
        self.b30 = RegisterAlias("b30", self.q30, size=1, offset=0)
        self.q31 = Register("q31", size=16)
        self.d31 = RegisterAlias("d31", self.q31, size=8, offset=0)
        self.s31 = RegisterAlias("s31", self.q31, size=4, offset=0)
        self.h31 = RegisterAlias("h31", self.q31, size=2, offset=0)
        self.b31 = RegisterAlias("b31", self.q31, size=1, offset=0)
        # *** Vector registers vX ***
        # I'm not sure how to model these.


class MIPSCPUState(CPU):
    """Auto-generated CPU state for mips:mips32:big

    Generated from Pcode language MIPS:BE:32:default,
    and Unicorn package unicorn.mips_const
    """

    # Excluded registers:
    # - zero: Hard-wired to zero
    # - at: Reserved for assembler
    # - kX: Reserved for kernel; used as general in some ABIs
    # - fX: Floating-point registers
    # - acX: Accumulator registers
    _GENERAL_PURPOSE_REGS = [
        "v0",
        "v1",
        "a0",
        "a1",
        "a2",
        "a3",
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
        "t6",
        "t7",
        "t8",
        "t9",
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "s8",
    ]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    def __init__(self):
        # NOTE: MIPS registers have both a name and a number.

        # *** General-Purpose Registers ***
        # Assembler-Temporary Register
        self.at = Register("at", size=4)
        self._1 = RegisterAlias("1", self.at, size=4, offset=0)
        # Return Value Registers
        self.v0 = Register("v0", size=4)
        self._2 = RegisterAlias("2", self.v0, size=4, offset=0)
        self.v1 = Register("v1", size=4)
        self._3 = RegisterAlias("3", self.v1, size=4, offset=0)
        # Argument Registers
        self.a0 = Register("a0", size=4)
        self._4 = RegisterAlias("4", self.a0, size=4, offset=0)
        self.a1 = Register("a1", size=4)
        self._5 = RegisterAlias("5", self.a1, size=4, offset=0)
        self.a2 = Register("a2", size=4)
        self._6 = RegisterAlias("6", self.a2, size=4, offset=0)
        self.a3 = Register("a3", size=4)
        self._7 = RegisterAlias("7", self.a3, size=4, offset=0)
        # Temporary Registers
        self.t0 = Register("t0", size=4)
        self._8 = RegisterAlias("8", self.t0, size=4, offset=0)
        self.t1 = Register("t1", size=4)
        self._9 = RegisterAlias("9", self.t1, size=4, offset=0)
        self.t2 = Register("t2", size=4)
        self._10 = RegisterAlias("10", self.t2, size=4, offset=0)
        self.t3 = Register("t3", size=4)
        self._11 = RegisterAlias("11", self.t3, size=4, offset=0)
        self.t4 = Register("t4", size=4)
        self._12 = RegisterAlias("12", self.t4, size=4, offset=0)
        self.t5 = Register("t5", size=4)
        self._13 = RegisterAlias("13", self.t5, size=4, offset=0)
        self.t6 = Register("t6", size=4)
        self._14 = RegisterAlias("14", self.t6, size=4, offset=0)
        self.t7 = Register("t7", size=4)
        self._15 = RegisterAlias("15", self.t7, size=4, offset=0)
        # NOTE: These numbers aren't out of order.
        # t8 and t9 are later in the register file than t0 - t7.
        self.t8 = Register("t8", size=4)
        self._24 = RegisterAlias("24", self.t8, size=4, offset=0)
        self.t9 = Register("t9", size=4)
        self._25 = RegisterAlias("25", self.t9, size=4, offset=0)
        # Saved Registers
        self.s0 = Register("s0", size=4)
        self._16 = RegisterAlias("16", self.s0, size=4, offset=0)
        self.s1 = Register("s1", size=4)
        self._17 = RegisterAlias("17", self.s1, size=4, offset=0)
        self.s2 = Register("s2", size=4)
        self._18 = RegisterAlias("18", self.s2, size=4, offset=0)
        self.s3 = Register("s3", size=4)
        self._19 = RegisterAlias("19", self.s3, size=4, offset=0)
        self.s4 = Register("s4", size=4)
        self._20 = RegisterAlias("20", self.s4, size=4, offset=0)
        self.s5 = Register("s5", size=4)
        self._21 = RegisterAlias("21", self.s5, size=4, offset=0)
        self.s6 = Register("s6", size=4)
        self._22 = RegisterAlias("22", self.s6, size=4, offset=0)
        self.s7 = Register("s7", size=4)
        self._23 = RegisterAlias("23", self.s7, size=4, offset=0)
        # NOTE: Register #30 was originally the Frame Pointer.
        # It's been re-aliased as s8, since many ABIs don't use the frame pointer.
        # Unicorn and Sleigh prefer to use the alias s8,
        # so it should be the base register.
        self.s8 = Register("s8", size=4)
        self.fp = RegisterAlias("fp", self.s8, size=4, offset=0)
        self._30 = RegisterAlias("30", self.s8, size=4, offset=0)
        # Kernel-reserved Registers
        self.k0 = Register("k0", size=4)
        self._26 = RegisterAlias("26", self.k0, size=4, offset=0)
        self.k1 = Register("k1", size=4)
        self._27 = RegisterAlias("27", self.k1, size=4, offset=0)
        # *** Pointer Registers ***
        # Zero register
        self.zero = Register("zero", size=4)
        self._0 = RegisterAlias("0", self.zero, size=4, offset=0)
        # Global Offset Pointer
        self.gp = Register("gp", size=4)
        self._28 = RegisterAlias("28", self.gp, size=4, offset=0)
        # Stack Pointer
        self.sp = Register("sp", size=4)
        self._29 = RegisterAlias("29", self.sp, size=4, offset=0)
        # Return Address
        self.ra = Register("ra", size=4)
        self._31 = RegisterAlias("31", self.ra, size=4, offset=0)
        # Program Counter
        self.pc = Register("pc", size=4)
        # Floating Point Registers
        self.f0 = Register("f0", size=4)
        self.f1 = Register("f1", size=4)
        self.f2 = Register("f2", size=4)
        self.f3 = Register("f3", size=4)
        self.f4 = Register("f4", size=4)
        self.f5 = Register("f5", size=4)
        self.f6 = Register("f6", size=4)
        self.f7 = Register("f7", size=4)
        self.f8 = Register("f8", size=4)
        self.f9 = Register("f9", size=4)
        self.f10 = Register("f10", size=4)
        self.f11 = Register("f11", size=4)
        self.f12 = Register("f12", size=4)
        self.f13 = Register("f13", size=4)
        self.f14 = Register("f14", size=4)
        self.f15 = Register("f15", size=4)
        self.f16 = Register("f16", size=4)
        self.f17 = Register("f17", size=4)
        self.f18 = Register("f18", size=4)
        self.f19 = Register("f19", size=4)
        self.f20 = Register("f20", size=4)
        self.f21 = Register("f21", size=4)
        self.f22 = Register("f22", size=4)
        self.f23 = Register("f23", size=4)
        self.f24 = Register("f24", size=4)
        self.f25 = Register("f25", size=4)
        self.f26 = Register("f26", size=4)
        self.f27 = Register("f27", size=4)
        self.f28 = Register("f28", size=4)
        self.f29 = Register("f29", size=4)
        self.f30 = Register("f30", size=4)
        self.f31 = Register("f31", size=4)
        # *** Floating Point Control Registers ***
        # NOTE: These are taken from Sleigh, and the MIPS docs.
        # Unicorn doesn't use these names, and has a different number of registers.
        self.fir = Register("fir", size=4)
        self.fcsr = Register("fcsr", size=4)
        self.fexr = Register("fexr", size=4)
        self.fenr = Register("fenr", size=4)
        self.fccr = Register("fccr", size=4)
        # TODO: MIPS has a boatload of extensions with their own registers.
        # There isn't a clean join between Sleigh, Unicorn, and MIPS docs.


class MIPSELCPUState(MIPSCPUState):
    """Auto-generated CPU state for mips:mips32:little

    Generated from Pcode language MIPS:LE:32:default,
    and Unicorn package unicorn.mips_const
    """

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.MIPS32, platform.Byteorder.LITTLE
        )

    def __init__(self):
        super().__init__()
        # *** Accumulator Registers ***
        # MIPS uses these to implement 64-bit results
        # from 32-bit multiplication, amongst others.
        self.ac0 = Register("ac0", size=8)
        self.lo = RegisterAlias("lo0", self.ac0, size=4, offset=0)
        self.hi = RegisterAlias("hi0", self.ac0, size=4, offset=4)
        self.ac1 = Register("ac1", size=8)
        self.lo1 = RegisterAlias("lo1", self.ac1, size=4, offset=0)
        self.hi1 = RegisterAlias("hi1", self.ac1, size=4, offset=4)
        self.ac2 = Register("ac2", size=8)
        self.lo2 = RegisterAlias("lo2", self.ac2, size=4, offset=0)
        self.hi2 = RegisterAlias("hi2", self.ac2, size=4, offset=4)
        self.ac3 = Register("ac3", size=8)
        self.lo3 = RegisterAlias("lo3", self.ac3, size=4, offset=0)
        self.hi3 = RegisterAlias("hi3", self.ac3, size=4, offset=4)


class MIPSBECPUState(MIPSCPUState):
    """Auto-generated CPU state for mips:mips32:big

    Generated from Pcode language MIPS:BE:32:default,
    and Unicorn package unicorn.mips_const
    """

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(platform.Architecture.MIPS32, platform.Byteorder.BIG)

    def __init__(self):
        super().__init__()
        # *** Accumulator Registers ***
        # MIPS uses these to implement 64-bit results
        # from 32-bit multiplication, amongst others.
        self.ac0 = Register("ac0", size=8)
        # NOTE: Be careful: there is also a 'hi' and 'lo' register;
        # they do different things.
        self.hi0 = RegisterAlias("hi0", self.ac0, size=4, offset=0)
        self.lo0 = RegisterAlias("lo0", self.ac0, size=4, offset=4)
        self.ac1 = Register("ac1", size=8)
        self.hi1 = RegisterAlias("hi1", self.ac1, size=4, offset=0)
        self.lo1 = RegisterAlias("lo1", self.ac1, size=4, offset=4)
        self.ac2 = Register("ac2", size=8)
        self.hi2 = RegisterAlias("hi2", self.ac2, size=4, offset=0)
        self.lo2 = RegisterAlias("lo2", self.ac2, size=4, offset=4)
        self.ac3 = Register("ac3", size=8)
        self.hi3 = RegisterAlias("hi3", self.ac3, size=4, offset=0)
        self.lo3 = RegisterAlias("lo3", self.ac3, size=4, offset=4)
        # TODO: MIPS has a boatload of extensions with their own registers.
        # There isn't a clean join between Sleigh, Unicorn, and MIPS docs.


class MIPS64CPUState(CPU):
    """Abstract CPU state object for all MIPS64 targets"""

    # Excluded registers:
    # - zero: Hard-wired to zero
    # - at: Reserved for assembler
    # - kX: Reserved for kernel; used as general in some ABIs
    # - fX: Floating-point registers
    # - acX: Accumulator registers
    _GENERAL_PURPOSE_REGS = [
        "v0",
        "v1",
        "a0",
        "a1",
        "a2",
        "a3",
        "a4",
        "a5",
        "a6",
        "a7",
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
        "t6",
        "t7",
        "t8",
        "t9",
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "s8",
    ]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    def __init__(self):
        # NOTE: MIPS registers have both a name and a number.

        # *** General-Purpose Registers ***
        # Assembler-Temporary Register
        self.at = Register("at", size=8)
        self._1 = RegisterAlias("1", self.at, size=8, offset=0)
        # Return Value Registers
        self.v0 = Register("v0", size=8)
        self._2 = RegisterAlias("2", self.v0, size=8, offset=0)
        self.v1 = Register("v1", size=8)
        self._3 = RegisterAlias("3", self.v1, size=8, offset=0)
        # Argument Registers
        self.a0 = Register("a0", size=8)
        self._4 = RegisterAlias("4", self.a0, size=8, offset=0)
        self.a1 = Register("a1", size=8)
        self._5 = RegisterAlias("5", self.a1, size=8, offset=0)
        self.a2 = Register("a2", size=8)
        self._6 = RegisterAlias("6", self.a2, size=8, offset=0)
        self.a3 = Register("a3", size=8)
        self._7 = RegisterAlias("7", self.a3, size=8, offset=0)
        # Temporary Registers
        # NOTE: Temp registers t0 - t3 are double-aliased as a4 - a7 in the n64 ABI
        self.t0 = Register("t0", size=8)
        self.a4 = RegisterAlias("a4", self.t0, size=8, offset=0)
        self._8 = RegisterAlias("8", self.t0, size=8, offset=0)
        self.t1 = Register("t1", size=8)
        self.a5 = RegisterAlias("a5", self.t1, size=8, offset=0)
        self._9 = RegisterAlias("9", self.t1, size=8, offset=0)
        self.t2 = Register("t2", size=8)
        self.a6 = RegisterAlias("a6", self.t2, size=8, offset=0)
        self._10 = RegisterAlias("10", self.t2, size=8, offset=0)
        self.t3 = Register("t3", size=8)
        self.a7 = RegisterAlias("a7", self.t3, size=8, offset=0)
        self._11 = RegisterAlias("11", self.t3, size=8, offset=0)
        self.t4 = Register("t4", size=8)
        self._12 = RegisterAlias("12", self.t4, size=8, offset=0)
        self.t5 = Register("t5", size=8)
        self._13 = RegisterAlias("13", self.t5, size=8, offset=0)
        self.t6 = Register("t6", size=8)
        self._14 = RegisterAlias("14", self.t6, size=8, offset=0)
        self.t7 = Register("t7", size=8)
        self._15 = RegisterAlias("15", self.t7, size=8, offset=0)
        # NOTE: These numbers aren't out of order.
        # t8 and t9 are later in the register file than t0 - t7.
        self.t8 = Register("t8", size=8)
        self._24 = RegisterAlias("24", self.t8, size=8, offset=0)
        self.t9 = Register("t9", size=8)
        self._25 = RegisterAlias("25", self.t9, size=8, offset=0)
        # Saved Registers
        self.s0 = Register("s0", size=8)
        self._16 = RegisterAlias("16", self.s0, size=8, offset=0)
        self.s1 = Register("s1", size=8)
        self._17 = RegisterAlias("17", self.s1, size=8, offset=0)
        self.s2 = Register("s2", size=8)
        self._18 = RegisterAlias("18", self.s2, size=8, offset=0)
        self.s3 = Register("s3", size=8)
        self._19 = RegisterAlias("19", self.s3, size=8, offset=0)
        self.s4 = Register("s4", size=8)
        self._20 = RegisterAlias("20", self.s4, size=8, offset=0)
        self.s5 = Register("s5", size=8)
        self._21 = RegisterAlias("21", self.s5, size=8, offset=0)
        self.s6 = Register("s6", size=8)
        self._22 = RegisterAlias("22", self.s6, size=8, offset=0)
        self.s7 = Register("s7", size=8)
        self._23 = RegisterAlias("23", self.s7, size=8, offset=0)
        # NOTE: Register #30 was originally the Frame Pointer.
        # It's been re-aliased as s8, since many ABIs don't use the frame pointer.
        # Unicorn and Sleigh prefer to use the alias s8,
        # so it should be the base register.
        self.s8 = Register("s8", size=8)
        self.fp = RegisterAlias("fp", self.s8, size=8, offset=0)
        self._30 = RegisterAlias("30", self.s8, size=8, offset=0)
        # Kernel-reserved Registers
        self.k0 = Register("k0", size=8)
        self._26 = RegisterAlias("26", self.k0, size=8, offset=0)
        self.k1 = Register("k1", size=8)
        self._27 = RegisterAlias("27", self.k1, size=8, offset=0)
        # *** Pointer Registers ***
        # Zero register
        self.zero = Register("zero", size=8)
        self._0 = RegisterAlias("0", self.zero, size=8, offset=0)
        # Global Offset Pointer
        self.gp = Register("gp", size=8)
        self._28 = RegisterAlias("28", self.gp, size=8, offset=0)
        # Stack Pointer
        self.sp = Register("sp", size=8)
        self._29 = RegisterAlias("29", self.sp, size=8, offset=0)
        # Return Address
        self.ra = Register("ra", size=8)
        self._31 = RegisterAlias("31", self.ra, size=8, offset=0)
        # Program Counter
        self.pc = Register("pc", size=8)
        # *** Floating Point Registers ***
        self.f1 = Register("f1", size=8)
        self.f0 = Register("f0", size=8)
        self.f3 = Register("f3", size=8)
        self.f2 = Register("f2", size=8)
        self.f5 = Register("f5", size=8)
        self.f4 = Register("f4", size=8)
        self.f7 = Register("f7", size=8)
        self.f6 = Register("f6", size=8)
        self.f9 = Register("f9", size=8)
        self.f8 = Register("f8", size=8)
        self.f11 = Register("f11", size=8)
        self.f10 = Register("f10", size=8)
        self.f13 = Register("f13", size=8)
        self.f12 = Register("f12", size=8)
        self.f15 = Register("f15", size=8)
        self.f14 = Register("f14", size=8)
        self.f17 = Register("f17", size=8)
        self.f16 = Register("f16", size=8)
        self.f19 = Register("f19", size=8)
        self.f18 = Register("f18", size=8)
        self.f21 = Register("f21", size=8)
        self.f20 = Register("f20", size=8)
        self.f23 = Register("f23", size=8)
        self.f22 = Register("f22", size=8)
        self.f25 = Register("f25", size=8)
        self.f24 = Register("f24", size=8)
        self.f27 = Register("f27", size=8)
        self.f26 = Register("f26", size=8)
        self.f29 = Register("f29", size=8)
        self.f28 = Register("f28", size=8)
        self.f31 = Register("f31", size=8)
        self.f30 = Register("f30", size=8)
        # *** Floating Point Control Registers ***
        # NOTE: These are taken from Sleigh, and the MIPS docs.
        # Unicorn doesn't use these names, and has a different number of registers.
        self.fir = Register("fir", size=8)
        self.fcsr = Register("fcsr", size=8)
        self.fexr = Register("fexr", size=8)
        self.fenr = Register("fenr", size=8)
        self.fccr = Register("fccr", size=8)


class MIPS64BECPUState(MIPS64CPUState):
    """Auto-generated CPU state for mips:mips32:big

    Generated from Pcode language MIPS:BE:32:default,
    and Unicorn package unicorn.mips_const
    """

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(platform.Architecture.MIPS64, platform.Byteorder.BIG)

    def __init__(self):
        super().__init__()
        # *** Accumulator Registers ***
        # MIPS uses these to implement 64-bit results
        # from 32-bit multiplication, amongst others.
        self.ac0 = Register("ac0", size=8)
        self.hi = RegisterAlias("hi0", self.ac0, size=8, offset=0)
        self.lo = RegisterAlias("lo0", self.ac0, size=8, offset=4)
        self.ac1 = Register("ac1", size=8)
        self.hi1 = RegisterAlias("hi1", self.ac1, size=8, offset=0)
        self.lo1 = RegisterAlias("lo1", self.ac1, size=8, offset=4)
        self.ac2 = Register("ac2", size=8)
        self.hi2 = RegisterAlias("hi2", self.ac2, size=8, offset=0)
        self.lo2 = RegisterAlias("lo2", self.ac2, size=8, offset=4)
        self.ac3 = Register("ac3", size=8)
        self.hi3 = RegisterAlias("hi3", self.ac3, size=8, offset=0)
        self.lo3 = RegisterAlias("lo3", self.ac3, size=8, offset=4)


class MIPS64ELCPUState(MIPS64CPUState):
    """Auto-generated CPU state for mips:mips32:little

    Generated from Pcode language MIPS:LE:32:default,
    and Unicorn package unicorn.mips_const
    """

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.MIPS64, platform.Byteorder.LITTLE
        )

    def __init__(self):
        super().__init__()
        # *** Accumulator Registers ***
        # MIPS uses these to implement 128-bit results
        # from 64-bit multiplication, amongst others.
        self.ac0 = Register("ac0", size=16)
        self.lo = RegisterAlias("lo0", self.ac0, size=8, offset=0)
        self.hi = RegisterAlias("hi0", self.ac0, size=8, offset=4)
        self.ac1 = Register("ac1", size=16)
        self.lo1 = RegisterAlias("lo1", self.ac1, size=8, offset=0)
        self.hi1 = RegisterAlias("hi1", self.ac1, size=8, offset=4)
        self.ac2 = Register("ac2", size=16)
        self.lo2 = RegisterAlias("lo2", self.ac2, size=8, offset=0)
        self.hi2 = RegisterAlias("hi2", self.ac2, size=8, offset=4)
        self.ac3 = Register("ac3", size=16)
        self.lo3 = RegisterAlias("lo3", self.ac3, size=8, offset=0)
        self.hi3 = RegisterAlias("hi3", self.ac3, size=8, offset=4)
        # TODO: MIPS has a boatload of extensions with their own registers.
        # There isn't a clean join between Sleigh, Unicorn, and MIPS docs.


class PowerPCCPUState(CPU):
    """CPU state for 32-bit PowerPC."""

    _GENERAL_PURPOSE_REGS = [f"r{i}" for i in range(0, 32)]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    def __init__(self, wordsize):
        # *** General Purpose Registers ***
        # NOTE: Used expressive names for GPRs and FPRs.
        # gasm just refers to GPRs and FPRS by number.
        # They use the same numbers; it's very annoying.
        self.r0 = Register("r0", size=wordsize)
        # NOTE: GPR 1 is also the stack pointer.
        self.r1 = Register("r1", size=wordsize)
        self.sp = RegisterAlias("sp", self.r1, size=wordsize, offset=0)
        self.r2 = Register("r2", size=wordsize)
        self.r3 = Register("r3", size=wordsize)
        self.r4 = Register("r4", size=wordsize)
        self.r5 = Register("r5", size=wordsize)
        self.r6 = Register("r6", size=wordsize)
        self.r7 = Register("r7", size=wordsize)
        self.r8 = Register("r8", size=wordsize)
        self.r9 = Register("r9", size=wordsize)
        self.r10 = Register("r10", size=wordsize)
        self.r11 = Register("r11", size=wordsize)
        self.r12 = Register("r12", size=wordsize)
        self.r13 = Register("r13", size=wordsize)
        self.r14 = Register("r14", size=wordsize)
        self.r15 = Register("r15", size=wordsize)
        self.r16 = Register("r16", size=wordsize)
        self.r17 = Register("r17", size=wordsize)
        self.r18 = Register("r18", size=wordsize)
        self.r19 = Register("r19", size=wordsize)
        self.r20 = Register("r20", size=wordsize)
        self.r21 = Register("r21", size=wordsize)
        self.r22 = Register("r22", size=wordsize)
        self.r23 = Register("r23", size=wordsize)
        self.r24 = Register("r24", size=wordsize)
        self.r25 = Register("r25", size=wordsize)
        self.r26 = Register("r26", size=wordsize)
        self.r27 = Register("r27", size=wordsize)
        self.r28 = Register("r28", size=wordsize)
        self.r29 = Register("r29", size=wordsize)
        self.r30 = Register("r30", size=wordsize)
        # NOTE: GPR 31 is also the base pointer
        self.r31 = Register("r31", size=wordsize)
        self.bp = RegisterAlias("bp", self.r31, size=wordsize, offset=0)

        # Floating Point Registers
        # Always 8 bytes, regardless of wordsize.
        self.f0 = Register("f0", size=8)
        self.f1 = Register("f1", size=8)
        self.f2 = Register("f2", size=8)
        self.f3 = Register("f3", size=8)
        self.f4 = Register("f4", size=8)
        self.f5 = Register("f5", size=8)
        self.f6 = Register("f6", size=8)
        self.f7 = Register("f7", size=8)
        self.f8 = Register("f8", size=8)
        self.f9 = Register("f9", size=8)
        self.f10 = Register("f10", size=8)
        self.f11 = Register("f11", size=8)
        self.f12 = Register("f12", size=8)
        self.f13 = Register("f13", size=8)
        self.f14 = Register("f14", size=8)
        self.f15 = Register("f15", size=8)
        self.f16 = Register("f16", size=8)
        self.f17 = Register("f17", size=8)
        self.f18 = Register("f18", size=8)
        self.f19 = Register("f19", size=8)
        self.f20 = Register("f20", size=8)
        self.f21 = Register("f21", size=8)
        self.f22 = Register("f22", size=8)
        self.f23 = Register("f23", size=8)
        self.f24 = Register("f24", size=8)
        self.f25 = Register("f25", size=8)
        self.f26 = Register("f26", size=8)
        self.f27 = Register("f27", size=8)
        self.f28 = Register("f28", size=8)
        self.f29 = Register("f29", size=8)
        self.f30 = Register("f30", size=8)
        self.f31 = Register("f31", size=8)

        # *** Pointer Registers ***
        # Program Counter.
        # Not really a register; nothing can access it directly
        self.pc = Register("pc", size=wordsize)

        # Link Register
        self.lr = Register("lr", size=wordsize)

        # Counter Register
        # Acts either as a loop index, or a branch target register
        # Only `ctr` and `lr` can act as branch targets.
        self.ctr = Register("ctr", size=wordsize)

        # *** Condition Registers ***
        # Condition Register
        # The actual condition register `cr` is a single 32-bit register,
        # but it's broken into eight 4-bit fields which are accessed separately.
        self.cr0 = Register("cr0", size=1)  # Integer condition bits
        self.cr1 = Register("cr1", size=1)  # Floatibg point condition bits
        self.cr2 = Register("cr2", size=1)
        self.cr3 = Register("cr3", size=1)
        self.cr4 = Register("cr4", size=1)
        self.cr5 = Register("cr5", size=1)
        self.cr6 = Register("cr6", size=1)
        self.cr7 = Register("cr7", size=1)

        # Integer Exception Register
        self.xer = Register("xer", size=4)

        # Floating Point Status and Control Register
        self.fpsrc = Register("fpscr", size=4)

        # TODO: This only focuses on the user-facing registrers.
        # ppc has a huge number of privileged registers.
        # Extend this as needed.


class PowerPC32CPUState(PowerPCCPUState):
    """CPU state for 32-bit PowerPC"""

    mode = "ppc32"

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.POWERPC32, platform.Byteorder.BIG
        )

    def __init__(self):
        super().__init__(4)


class PowerPC64CPUState(PowerPCCPUState):
    """CPU state for 64-bit PowerPC"""

    mode = "ppc64"

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.POWERPC64, platform.Byteorder.BIG
        )

    def __init__(self):
        super().__init__(8)


# ARM32 has a number of variants with very odd overlaps.
# Rather than risk copy-paste errors as I figure out who gets which control registers,
# I've implemented each subsystem variant in its own mixin.


class ARMCPUState(CPU):
    """Base class for ARM 32-bit CPU models

    All ARM CPUs share the same basic registers,
    but there are at least two dimensions of difference
    for the available modes.
    """

    # Special registers:
    # r13: stack pointer
    # r14: link register
    # r15: Program counter
    _GENERAL_PURPOSE_REGS = [f"r{i}" for i in range(0, 13)]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    def __init__(self):
        # *** General-purpose registers ***
        self.r0 = Register("r0", size=4)
        self.r1 = Register("r1", size=4)
        self.r2 = Register("r2", size=4)
        self.r3 = Register("r3", size=4)
        self.r4 = Register("r4", size=4)
        self.r5 = Register("r5", size=4)
        self.r6 = Register("r6", size=4)
        self.r7 = Register("r7", size=4)
        self.r8 = Register("r8", size=4)
        # r9 doubles as the Static base pointer
        self.r9 = Register("r9", size=4)
        self.sb = RegisterAlias("sb", self.r9, size=4, offset=0)
        # r10 doubles as the Stack Limit pointer
        self.r10 = Register("r10", size=4)
        self.sl = RegisterAlias("sl", self.r10, size=4, offset=0)
        # r11 doubles as the Frame Pointer, if desired.
        self.r11 = Register("r11", size=4)
        self.fp = RegisterAlias("fp", self.r11, size=4, offset=0)
        # r12 doubles as the Intra-call scratch register
        self.r12 = Register("r12", size=4)
        self.ip = RegisterAlias("ip", self.r12, size=4, offset=0)
        self.sp = Register("sp", size=4)
        self.lr = Register("lr", size=4)
        self.pc = Register("pc", size=4)


class ARMCPUMixinM:
    """Abstract class for M-series CPUs.

    The main difference between M and R/A
    is the available system status registers.
    """

    def __init__(self):
        super().__init__()
        # *** Special Registers ***
        # Program Status Register
        # NOTE: PSR can be accessed through several masked aliases.
        # These are read-only, so I'm not including them.
        # - apsr: Just the condition flags
        # - ipsr: Just exception information
        # - epsr: Just execution state info
        # - iapsr: apsr | ipsr
        # - eapsr: apsr | epsr
        # - iepsr: ipsr | epsr
        # - xpsr: apsr | ipsr | epsr
        #
        # NOTE: Unicorn doesn't have a model for PSR, only its aliases
        self.psr = Register("psr", size=4)
        # Exception Mask Register
        self.primask = Register("primask", size=4)
        # Base Priority Mask Register
        self.basepri = Register("basepri", size=4)
        # Fault Mask Register
        self.faultmask = Register("faultmask", size=4)
        # Control register; includes a lot of flags.
        self.control = Register("control", size=4)

        # *** Stack Pointer Bank ***
        # sp is actually an alias to one of these two.
        # Exactly which one depends on a bit in control.
        # Emulators that care should be careful when loading state.

        # Main Stack Pointer
        self.msp = Register("msp", size=4)
        # Process Stack Pointer
        self.psp = Register("psp", size=4)


class ARMCPUMixinRA:
    """Mixin for R- or A-series CPUs.

    The main difference between M and R/A
    is the available system status registers.
    """

    def __init__(self):
        super().__init__()
        # *** Special Registers ***
        # Current Program Status Register
        # NOTE: CPSR can be accessed through several masked aliases.
        # These are read-only, so I'm not including them.
        # - isetstate: Just includes instruction set control bits
        # - itstate: Just includes state bits for Thumb IT instruction
        self.cpsr = Register("cpsr", size=4)
        # Saved Program Status Register
        self.spsr = Register("spsr", size=4)

        # *** Register Banks ***
        # sp, lr, and spsr are actually aliases to one of these.
        # Which one they reference depends on execution mode.
        # Emulators that care should be careful when loading state.
        # NOTE: Use User-mode copies of registers unless the mode has its own.

        # User-mode Stack Pointer
        self.sp_usr = Register("sp_usr", size=4)
        # User-mode Link Register
        self.lr_usr = Register("lr_usr", size=4)
        # User-mode r8
        self.r8_usr = Register("r8_usr", size=4)
        # User-mode r9
        self.r9_usr = Register("r9_usr", size=4)
        # User-mode r10
        self.r10_usr = Register("r10_usr", size=4)
        # User-mode r11
        self.r11_usr = Register("r11_usr", size=4)
        # User-mode r12
        self.r12_usr = Register("r12_usr", size=4)

        # Hypervisor Stack Pointer
        self.sp_hyp = Register("sp_hyp", size=4)
        # Hypervisor Saved PSR
        self.spsr_hyp = Register("spsr_hyp", size=4)
        # Hypervisor Exception Link Register
        # NOTE: This isn't so much banked, as it only exists in hypervisor mode.
        self.elr_hyp = Register("elr_hyp", size=4)

        # Supervisor Stack Pointer
        self.sp_svc = Register("sp_svc", size=4)
        # Supervisor Link Register
        self.lr_svc = Register("lr_svc", size=4)
        # Supervisor Saved PSR
        self.spsr_svc = Register("spsr_svc", size=4)

        # Abort-state Stack Pointer
        self.sp_abt = Register("sp_abt", size=4)
        # Abort-state Link Register
        self.lr_abt = Register("lr_abt", size=4)
        # Abort-state Saved PSR
        self.spsr_abt = Register("spsr_abt", size=4)

        # Undefined-mode Stack Pointer
        self.sp_und = Register("sp_und", size=4)
        # Undefined-mode Link Register
        self.lr_und = Register("lr_und", size=4)
        # Undefined-mode Saved PSR
        self.spsr_und = Register("spsr_und", size=4)

        # Monitor-mode Stack Pointer
        self.sp_mon = Register("sp_mon", size=4)
        # Monitor-mode Link Register
        self.lr_mon = Register("lr_mon", size=4)
        # Monitor-mode Saved PSR
        self.spsr_mon = Register("spsr_mon", size=4)

        # IRQ-mode Stack Pointer
        self.sp_irq = Register("sp_irq", size=4)
        # IRQ-mode Link Register
        self.lr_irq = Register("lr_irq", size=4)
        # IRQ-mode Saved PSR
        self.spsr_irq = Register("spsr_irq", size=4)

        # FIQ-mode Stack Pointer
        self.sp_fiq = Register("sp_fiq", size=4)
        # FIQ-mode Link Register
        self.lr_fiq = Register("lr_fiq", size=4)
        # FIQ-mode Saved PSR
        self.spsr_fiq = Register("spsr_fiq", size=4)
        # FIQ-mode r8
        self.r8_fiq = Register("r8_fiq", size=4)
        # FIQ-mode r9
        self.r9_fiq = Register("r9_fiq", size=4)
        # FIQ-mode r10
        self.r10_fiq = Register("r10_fiq", size=4)
        # FIQ-mode r11
        self.r11_fiq = Register("r11_fiq", size=4)
        # FIQ-mode r12
        self.r12_fiq = Register("r12_fiq", size=4)


class ARMCPUMixinFPEL:
    """Mixin for little-endian ARM CPUs with FP extensions

    This is one kind of floating-point extension
    which offers 64-bit scalar operations
    """

    def __init__(self):
        super().__init__()
        # *** Floating point control registers ***
        # Floating-point Status and Control Register
        self.fpscr = Register("fpscr", size=4)
        # Floating-point Exception Control Register
        self.fpexc = Register("fpexc", size=4)
        # Floating-point System ID Register
        self.fpsid = Register("fpsid", size=4)
        # Media and VFP Feature Register 0
        self.mvfr0 = Register("mvfr0", size=4)
        # Media and VFP Feature Register 1
        self.mvfr1 = Register("mvfr1", size=4)

        # *** Floating point registers ***
        self.d0 = Register("d0", size=8)
        self.s0 = RegisterAlias("s0", self.d0, size=4, offset=0)
        self.s1 = RegisterAlias("s1", self.d0, size=4, offset=4)
        self.d1 = Register("d1", size=8)
        self.s2 = RegisterAlias("s2", self.d1, size=4, offset=0)
        self.s3 = RegisterAlias("s3", self.d1, size=4, offset=4)
        self.d2 = Register("d2", size=8)
        self.s4 = RegisterAlias("s4", self.d2, size=4, offset=0)
        self.s5 = RegisterAlias("s5", self.d2, size=4, offset=4)
        self.d3 = Register("d3", size=8)
        self.s6 = RegisterAlias("s6", self.d3, size=4, offset=0)
        self.s7 = RegisterAlias("s7", self.d3, size=4, offset=4)
        self.d4 = Register("d4", size=8)
        self.s8 = RegisterAlias("s8", self.d4, size=4, offset=0)
        self.s9 = RegisterAlias("s9", self.d4, size=4, offset=4)
        self.d5 = Register("d5", size=8)
        self.s10 = RegisterAlias("s10", self.d5, size=4, offset=0)
        self.s11 = RegisterAlias("s11", self.d5, size=4, offset=4)
        self.d6 = Register("d6", size=8)
        self.s12 = RegisterAlias("s12", self.d6, size=4, offset=0)
        self.s13 = RegisterAlias("s13", self.d6, size=4, offset=4)
        self.d7 = Register("d7", size=8)
        self.s14 = RegisterAlias("s14", self.d7, size=4, offset=0)
        self.s15 = RegisterAlias("s15", self.d7, size=4, offset=4)
        self.d8 = Register("d8", size=8)
        self.s16 = RegisterAlias("s16", self.d8, size=4, offset=0)
        self.s17 = RegisterAlias("s17", self.d8, size=4, offset=4)
        self.d9 = Register("d9", size=8)
        self.s18 = RegisterAlias("s18", self.d9, size=4, offset=0)
        self.s19 = RegisterAlias("s19", self.d9, size=4, offset=4)
        self.d10 = Register("d10", size=8)
        self.s20 = RegisterAlias("s20", self.d10, size=4, offset=0)
        self.s21 = RegisterAlias("s21", self.d10, size=4, offset=4)
        self.d11 = Register("d11", size=8)
        self.s22 = RegisterAlias("s22", self.d11, size=4, offset=0)
        self.s23 = RegisterAlias("s23", self.d11, size=4, offset=4)
        self.d12 = Register("d12", size=8)
        self.s24 = RegisterAlias("s24", self.d12, size=4, offset=0)
        self.s25 = RegisterAlias("s25", self.d12, size=4, offset=4)
        self.d13 = Register("d13", size=8)
        self.s26 = RegisterAlias("s26", self.d13, size=4, offset=0)
        self.s27 = RegisterAlias("s27", self.d13, size=4, offset=4)
        self.d14 = Register("d14", size=8)
        self.s28 = RegisterAlias("s28", self.d14, size=4, offset=0)
        self.s29 = RegisterAlias("s29", self.d14, size=4, offset=4)
        self.d15 = Register("d15", size=8)
        self.s30 = RegisterAlias("s30", self.d15, size=4, offset=0)
        self.s31 = RegisterAlias("s31", self.d15, size=4, offset=4)


class ARMCPUMixinVFPEL:
    """Mixin for little-endian ARM CPUs with VFP/NEON mixins

    This is one kind of floating-point extension
    which supports up to 128-bit scalar and SIMD vector operations.

    VFP and NEON are always optional extensions;
    The two can exist independently, and VFP can support either
    16 or 32 double registers.
    This is the maximal set of registers, assuming both are supported.
    """

    def __init__(self):
        super().__init__()
        # *** Floating-point Control Registers ***
        # Floating-point Status and Control Register
        self.fpscr = Register("fpscr", size=4)
        # Floating-point Exception Control Register
        self.fpexc = Register("fpexc", size=4)
        # Floating-point System ID Register
        self.fpsid = Register("fpsid", size=4)
        # Media and VFP Feature Register 0
        self.mvfr0 = Register("mvfr0", size=4)
        # Media and VFP Feature Register 1
        self.mvfr1 = Register("mvfr1", size=4)
        # *** Floating-point Registers ****
        self.q0 = Register("q0", size=16)
        self.d0 = RegisterAlias("d0", self.q0, size=8, offset=0)
        self.s0 = RegisterAlias("s0", self.q0, size=4, offset=0)
        self.s1 = RegisterAlias("s1", self.q0, size=4, offset=4)
        self.d1 = RegisterAlias("d1", self.q0, size=8, offset=8)
        self.s2 = RegisterAlias("s2", self.q0, size=4, offset=8)
        self.s3 = RegisterAlias("s3", self.q0, size=4, offset=12)
        self.q1 = Register("q1", size=16)
        self.d2 = RegisterAlias("d2", self.q1, size=8, offset=0)
        self.s4 = RegisterAlias("s4", self.q1, size=4, offset=0)
        self.s5 = RegisterAlias("s5", self.q1, size=4, offset=4)
        self.d3 = RegisterAlias("d3", self.q1, size=8, offset=8)
        self.s6 = RegisterAlias("s6", self.q1, size=4, offset=8)
        self.s7 = RegisterAlias("s7", self.q1, size=4, offset=12)
        self.q2 = Register("q2", size=16)
        self.d4 = RegisterAlias("d4", self.q2, size=8, offset=0)
        self.s8 = RegisterAlias("s8", self.q2, size=4, offset=0)
        self.s9 = RegisterAlias("s9", self.q2, size=4, offset=4)
        self.d5 = RegisterAlias("d5", self.q2, size=8, offset=8)
        self.s10 = RegisterAlias("s10", self.q2, size=4, offset=8)
        self.s11 = RegisterAlias("s11", self.q2, size=4, offset=12)
        self.q3 = Register("q3", size=16)
        self.d6 = RegisterAlias("d6", self.q3, size=8, offset=0)
        self.s12 = RegisterAlias("s12", self.q3, size=4, offset=0)
        self.s13 = RegisterAlias("s13", self.q3, size=4, offset=4)
        self.d7 = RegisterAlias("d7", self.q3, size=8, offset=8)
        self.s14 = RegisterAlias("s14", self.q3, size=4, offset=8)
        self.s15 = RegisterAlias("s15", self.q3, size=4, offset=12)
        self.q4 = Register("q4", size=16)
        self.d8 = RegisterAlias("d8", self.q4, size=8, offset=0)
        self.s16 = RegisterAlias("s16", self.q4, size=4, offset=0)
        self.s17 = RegisterAlias("s17", self.q4, size=4, offset=4)
        self.d9 = RegisterAlias("d9", self.q4, size=8, offset=8)
        self.s18 = RegisterAlias("s18", self.q4, size=4, offset=8)
        self.s19 = RegisterAlias("s19", self.q4, size=4, offset=12)
        self.q5 = Register("q5", size=16)
        self.d10 = RegisterAlias("d10", self.q5, size=8, offset=0)
        self.s20 = RegisterAlias("s20", self.q5, size=4, offset=0)
        self.s21 = RegisterAlias("s21", self.q5, size=4, offset=4)
        self.d11 = RegisterAlias("d11", self.q5, size=8, offset=8)
        self.s22 = RegisterAlias("s22", self.q5, size=4, offset=8)
        self.s23 = RegisterAlias("s23", self.q5, size=4, offset=12)
        self.q6 = Register("q6", size=16)
        self.d12 = RegisterAlias("d12", self.q6, size=8, offset=0)
        self.s24 = RegisterAlias("s24", self.q6, size=4, offset=0)
        self.s25 = RegisterAlias("s25", self.q6, size=4, offset=4)
        self.d13 = RegisterAlias("d13", self.q6, size=8, offset=8)
        self.s26 = RegisterAlias("s26", self.q6, size=4, offset=8)
        self.s27 = RegisterAlias("s27", self.q6, size=4, offset=12)
        self.q7 = Register("q7", size=16)
        self.d14 = RegisterAlias("d14", self.q7, size=8, offset=0)
        self.s28 = RegisterAlias("s28", self.q7, size=4, offset=0)
        self.s29 = RegisterAlias("s29", self.q7, size=4, offset=4)
        self.d15 = RegisterAlias("d15", self.q7, size=8, offset=8)
        self.s30 = RegisterAlias("s30", self.q7, size=4, offset=8)
        self.s31 = RegisterAlias("s31", self.q7, size=4, offset=12)
        # NOTE: This isn't a typo; there are only 32 single-precision sX registers
        # This does mean that only half the VFP register space can be used
        # for single-precision arithmetic.
        self.q8 = Register("q8", size=16)
        self.d16 = RegisterAlias("d16", self.q8, size=8, offset=0)
        self.d17 = RegisterAlias("d17", self.q8, size=8, offset=8)
        self.q9 = Register("q9", size=16)
        self.d18 = RegisterAlias("d18", self.q9, size=8, offset=0)
        self.d19 = RegisterAlias("d19", self.q9, size=8, offset=8)
        self.q10 = Register("q10", size=16)
        self.d20 = RegisterAlias("d20", self.q10, size=8, offset=0)
        self.d21 = RegisterAlias("d21", self.q10, size=8, offset=8)
        self.q11 = Register("q11", size=16)
        self.d22 = RegisterAlias("d22", self.q11, size=8, offset=0)
        self.d23 = RegisterAlias("d23", self.q11, size=8, offset=8)
        self.q12 = Register("q12", size=16)
        self.d24 = RegisterAlias("d24", self.q12, size=8, offset=0)
        self.d25 = RegisterAlias("d25", self.q12, size=8, offset=8)
        self.q13 = Register("q13", size=16)
        self.d26 = RegisterAlias("d26", self.q13, size=8, offset=0)
        self.d27 = RegisterAlias("d27", self.q13, size=8, offset=8)
        self.q14 = Register("q14", size=16)
        self.d28 = RegisterAlias("d28", self.q14, size=8, offset=0)
        self.d29 = RegisterAlias("d29", self.q14, size=8, offset=8)
        self.q15 = Register("q15", size=16)
        self.d30 = RegisterAlias("d30", self.q15, size=8, offset=0)
        self.d31 = RegisterAlias("d31", self.q15, size=8, offset=8)


class ARMv5TCPUState(ARMCPUMixinM, ARMCPUState):
    """CPU Model for ARMv5t little-endian"""

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.ARM_V5T, platform.Byteorder.LITTLE
        )


class ARMv6MCPUState(ARMCPUMixinFPEL, ARMCPUMixinM, ARMCPUState):
    """CPU Model for ARMv6-M little-endian"""

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.ARM_V6M, platform.Byteorder.LITTLE
        )


class ARMv6MThumbCPUState(ARMv6MCPUState):
    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.ARM_V6M_THUMB, platform.Byteorder.LITTLE
        )


class ARMv7MCPUState(ARMCPUMixinFPEL, ARMCPUMixinM, ARMCPUState):
    """CPU Model for ARMv7-M little-endian"""

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.ARM_V7M, platform.Byteorder.LITTLE
        )


class ARMv7RCPUState(ARMCPUMixinVFPEL, ARMCPUMixinRA, ARMCPUState):
    """CPU Model for ARMv7-R little-endian"""

    # TODO: v7r and v7a have different MMUs, which I don't implement yet.
    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.ARM_V7R, platform.Byteorder.LITTLE
        )


class ARMv7ACPUState(ARMCPUMixinVFPEL, ARMCPUMixinRA, ARMCPUState):
    """CPU Model for ARMv7-A little-endian"""

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(
            platform.Architecture.ARM_V7A, platform.Byteorder.LITTLE
        )


__all__ = ["Stateful", "Value", "Register", "RegisterAlias", "Memory", "Machine", "CPU"]
