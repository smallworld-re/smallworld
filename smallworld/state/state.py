import abc
import typing

from .. import emulators, platform, utils
import smallworld

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

class StatefulSet(Stateful):
    def __init__(self):
        self._states = []

    def extract(self, emulator: emulators.Emulator) -> None:
        for s in self._states:
            s.extract(emulator)

    def apply(self, emulator: emulators.Emulator) -> None:
        for s in self._states:
            s.apply(emulator)

    def add(self, s: Stateful):
        self._states.append(s)

class CPU(StatefulSet):
    @classmethod
    @abc.abstractmethod
    def get_platform(self) -> platform.Platform:
        pass

    @classmethod
    def for_platform(cls, platform: platform.Platform):
        try:
            return utils.find_subclass(cls,lambda x: x.get_platform().architecture == platform.architecture and x.get_platform().byteorder == platform.byteorder)
        except ValueError:
            raise ValueError(f"No CPU model for {platform.architecture}:{platform.byteorder}")

    @abc.abstractmethod
    def get_general_purpose_registers(self) -> typing.List[str]:
        pass

    def __repr__(self) -> str:
        p = self.get_platform()
        return f"{p.architecture} - {p.byteorder}"


class Machine(StatefulSet):
    pass

class Value(Stateful):
    """An individual state value."""

    _content: typing.Optional[typing.Any] = None
    """Stored value."""

    _type: typing.Optional[typing.Any] = None
    """Type object/class."""

    _label: typing.Optional[str] = None
    """A useful label."""

    size: int = 0
    """Size in bytes."""

    def get(self):
        return self.get_content()

    def set(self, content):
        return self.set_content(content)

    def get_content(self):
        return self._content

    def set_content(self, content):
        self._content = content

    def get_type(self):
        return self._type

    def set_type(self, type):
        self._type = type

    def get_label(self):
        return self._label

    def set_label(self, label):
        self._label = label

    @abc.abstractmethod
    def to_bytes(self, byteorder: platform.Byteorder) -> bytes:
        """Convert content to bytes."""

        return b""

    @classmethod
    def from_ctypes(cls, value: typing.Any):
        """Load from an existing ctypes object."""

        raise NotImplementedError("TODO")

class Register(Value):
    """An individual register.

    Arguments:
        name: The canonical name of the register.
        size: The width (in bytes) of the register.
    """

    _content: typing.Optional[int] = None
    _type = None
    _label = None

    size = 0
    """Register width in bytes."""

    def __init__(self, name: str, size: int = 4):
        super().__init__()

        self.name: str = name
        """Canonical name."""

        self.size = size

    def extract(self, emulator: emulators.Emulator) -> None:
        self._content = emulator.read_register_content(self.name)
        self._type = emulator.read_register_type(self.name)
        self._label = emulator.read_register_label(self.name)

    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_register_content(self.name, self._content)
        emulator.write_register_type(self.name, self._type)
        emulator.write_register_label(self.name, self._label)


    def to_bytes(self, byteorder: platform.Byteorder) -> bytes:
        """Convert content to bytes."""
        if byteorder == platform.Byteorder.LITTLE:
            return self._content.to_bytes(self.size, byteorder='little')
        elif byteorder == platform.Byteorder.BIG:
            return self._content.to_bytes(self.size, byteorder='big')
        else:
            b""

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

        self.offset = offset
        """'The offset into the referenced register."""

    @property
    def mask(self) -> int:
        """Generate a mask for this partial register."""

        mask = (1 << self.width * 8) - 1
        mask <<= self.offset * 8

        return mask

    def extract(self, emulator: emulators.Emulator) -> None:
        self.reference.get(emulator)

        self.content = self.reference.content & self.mask
        self.content >>= self.offset * 8

        self.type = self.reference.type
        self.label = self.reference.label

    def apply(self, emulator: emulators.Emulator) -> None:
        reference = self.reference.content or 0
        result = (reference & ~self.mask) + value
        self.reference.content = result

        self.reference.type = self.type
        self.reference.label = self.label

        self.reference.set(emulator)

class Memory(Stateful):
    def __init__(self, address, size) -> None:
        super().__init__()
        self._address = address
        self._size = size


    def apply(self, emulator: emulators.Emulator) -> None:
        emulator.write_memory(self._address, self.get_bytes())

    def extract(self, emulator: emulators.Emulator) -> None:
        raise NotImplemented

class Code(Memory):
    pass


class i386CPUState(CPU):
    """i386 CPU state model."""

    _GENERAL_PURPOSE_REGS = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"]

    def get_general_purpose_registers(self) -> typing.List[str]:
        return self._GENERAL_PURPOSE_REGS

    @classmethod
    def get_platform(cls) -> platform.Platform:
        return platform.Platform(platform.Architecture.X86_32, platform.Byteorder.LITTLE)

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
        return platform.Platform(platform.Architecture.X86_64, platform.Byteorder.LITTLE)

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

__all__ = ["Stateful", "Value", "Register", "RegisterAlias", "Machine", "CPU"]
