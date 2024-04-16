from __future__ import annotations

import logging
import sys
import typing

import capstone
import unicorn

from .. import exceptions, instructions, state
from . import emulator

logger = logging.getLogger(__name__)


class UnicornEmulator(emulator.Emulator):
    """An emulator for the Unicorn emulation engine.

    Arguments:
        arch: Unicorn architecture constant.
        mode: Unicorn mode constant.
    """

    ARCHITECTURES = {"x86": unicorn.UC_ARCH_X86}

    MODES = {"32": unicorn.UC_MODE_32, "64": unicorn.UC_MODE_64}

    I386_REGISTERS = {
        "ah": unicorn.x86_const.UC_X86_REG_AH,
        "al": unicorn.x86_const.UC_X86_REG_AL,
        "eax": unicorn.x86_const.UC_X86_REG_EAX,
        "bh": unicorn.x86_const.UC_X86_REG_BH,
        "bl": unicorn.x86_const.UC_X86_REG_BL,
        "ebx": unicorn.x86_const.UC_X86_REG_EBX,
        "ch": unicorn.x86_const.UC_X86_REG_CH,
        "cl": unicorn.x86_const.UC_X86_REG_CL,
        "ecx": unicorn.x86_const.UC_X86_REG_ECX,
        "dh": unicorn.x86_const.UC_X86_REG_DH,
        "dl": unicorn.x86_const.UC_X86_REG_DL,
        "edx": unicorn.x86_const.UC_X86_REG_EDX,
        "esi": unicorn.x86_const.UC_X86_REG_ESI,
        "edi": unicorn.x86_const.UC_X86_REG_EDI,
        "ebp": unicorn.x86_const.UC_X86_REG_EBP,
        "esp": unicorn.x86_const.UC_X86_REG_ESP,
        "eip": unicorn.x86_const.UC_X86_REG_EIP,
        "cs": unicorn.x86_const.UC_X86_REG_CS,
        "ds": unicorn.x86_const.UC_X86_REG_DS,
        "es": unicorn.x86_const.UC_X86_REG_ES,
        "fs": unicorn.x86_const.UC_X86_REG_FS,
        "gs": unicorn.x86_const.UC_X86_REG_GS,
        "eflags": unicorn.x86_const.UC_X86_REG_EFLAGS,
        "cr0": unicorn.x86_const.UC_X86_REG_CR0,
        "cr1": unicorn.x86_const.UC_X86_REG_CR1,
        "cr2": unicorn.x86_const.UC_X86_REG_CR2,
        "cr3": unicorn.x86_const.UC_X86_REG_CR3,
        "cr4": unicorn.x86_const.UC_X86_REG_CR4,
    }

    AMD64_REGISTERS = {
        "rax": unicorn.x86_const.UC_X86_REG_RAX,
        "rbx": unicorn.x86_const.UC_X86_REG_RBX,
        "rcx": unicorn.x86_const.UC_X86_REG_RCX,
        "rdx": unicorn.x86_const.UC_X86_REG_RDX,
        "r8": unicorn.x86_const.UC_X86_REG_R8,
        "r9": unicorn.x86_const.UC_X86_REG_R9,
        "r10": unicorn.x86_const.UC_X86_REG_R10,
        "r11": unicorn.x86_const.UC_X86_REG_R11,
        "r12": unicorn.x86_const.UC_X86_REG_R12,
        "r13": unicorn.x86_const.UC_X86_REG_R13,
        "r14": unicorn.x86_const.UC_X86_REG_R14,
        "r15": unicorn.x86_const.UC_X86_REG_R15,
        "rsi": unicorn.x86_const.UC_X86_REG_RSI,
        "rdi": unicorn.x86_const.UC_X86_REG_RDI,
        "rbp": unicorn.x86_const.UC_X86_REG_RBP,
        "rsp": unicorn.x86_const.UC_X86_REG_RSP,
        "rip": unicorn.x86_const.UC_X86_REG_RIP,
        "rflags": unicorn.x86_const.UC_X86_REG_RFLAGS,
    }

    REGISTERS = {
        unicorn.UC_ARCH_X86: {
            unicorn.UC_MODE_32: I386_REGISTERS,
            unicorn.UC_MODE_64: {
                **I386_REGISTERS,
                **AMD64_REGISTERS,
            },
        }
    }

    CAPSTONE_ARCH_MAP = {unicorn.UC_ARCH_X86: capstone.CS_ARCH_X86}

    CAPSTONE_MODE_MAP = {
        unicorn.UC_MODE_32: capstone.CS_MODE_32,
        unicorn.UC_MODE_64: capstone.CS_MODE_64,
    }

    def __init__(self, arch: str, mode: str):
        super().__init__()

        arch = arch.lower()
        if arch not in self.ARCHITECTURES:
            raise ValueError(f"unsupported architecture: {arch}")
        self.arch = self.ARCHITECTURES[arch]

        mode = mode.lower()
        if mode not in self.MODES:
            raise ValueError(f"unsupported processor mode: {mode}")
        self.mode = self.MODES[mode]

        if self.arch not in self.REGISTERS:
            raise ValueError("unsupported architecture")

        if self.mode not in self.REGISTERS[self.arch]:
            raise ValueError("unsupported mode for current architecture")

        self.entry: typing.Optional[int] = None

        self.engine = unicorn.Uc(self.arch, self.mode)

        self.disassembler = capstone.Cs(
            self.CAPSTONE_ARCH_MAP[self.arch], self.CAPSTONE_MODE_MAP[self.mode]
        )
        self.disassembler.detail = True
        self.bounds: typing.Iterable[range] = []

        self.hooks: typing.Dict[int, typing.Callable[[emulator.Emulator], None]] = {}
        self.hook_return = None

        def callback(uc, address, size, user_data):
            if address in self.hooks:
                self.hooks[address](self)
                if self.hook_return is not None:
                    self.write_register("pc", self.hook_return)
                    self.hook_return = None

            self.hook_return = address + size

        self.engine.hook_add(unicorn.UC_HOOK_CODE, callback)

    def register(self, name: str) -> int:
        """Translate register name into Unicorn constant.

        Arguments:
            register (str): Canonical name of a register.

        Returns:
            The Unicorn constant corresponding to the given register name.
        """

        name = name.lower()

        # support some generic register references
        if name == "pc":
            if self.arch == unicorn.UC_ARCH_X86:
                if self.mode == unicorn.UC_MODE_32:
                    name = "eip"
                elif self.mode == unicorn.UC_MODE_64:
                    name = "rip"
                else:
                    raise NotImplementedError(
                        f"no idea how to get pc for x86 mode [{self.mode}]"
                    )
            else:
                raise NotImplementedError(
                    f"no idea how to get pc for arch [{self.arch}]"
                )

        try:
            return self.REGISTERS[self.arch][self.mode][name]
        except KeyError:
            raise ValueError(f"unknown or unsupported register '{name}'")

    def read_register(self, name: str) -> int:
        return self.engine.reg_read(self.register(name))

    def write_register(self, name: str, value: typing.Optional[int]) -> None:
        if value is None:
            logger.debug(f"ignoring register write to {name} - no value")
            return

        self.engine.reg_write(self.register(name), value)

        logger.debug(f"set register {name}={value}")

    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        if size > sys.maxsize:
            raise ValueError(f"{size} is too large (max: {sys.maxsize})")

        try:
            return self.engine.mem_read(address, size)
        except unicorn.unicorn.UcError:
            logger.warn(f"attempted to read uninitialized memory at 0x{address:x}")
            return None

    PAGE_SIZE = 0x1000

    def write_memory(self, address: int, value: typing.Optional[bytes]) -> None:
        if value is None:
            raise ValueError(f"{self.__class__.__name__} requires concrete state")

        if len(value) > sys.maxsize:
            raise ValueError(f"{len(value)} is too large (max: {sys.maxsize})")

        if not len(value):
            raise ValueError("memory write cannot be empty")

        def page(address):
            return address // self.PAGE_SIZE

        def subtract(first, second):
            result = []
            endpoints = sorted((*first, *second))
            if endpoints[0] == first[0] and endpoints[1] != first[0]:
                result.append((endpoints[0], endpoints[1]))
            if endpoints[3] == first[1] and endpoints[2] != first[1]:
                result.append((endpoints[2], endpoints[3]))

            return result

        def map(start, end):
            address = start * self.PAGE_SIZE
            allocation = (end - start) * self.PAGE_SIZE

            logger.debug(f"new memory map 0x{address:x}[{allocation}]")

            self.engine.mem_map(address, allocation)

        region = (page(address), page(address + len(value)) + 1)

        for start, end, _ in self.engine.mem_regions():
            mapped = (page(start), page(end) + 1)

            regions = subtract(region, mapped)

            if len(regions) == 0:
                break
            elif len(regions) == 1:
                region = regions[0]
            elif len(regions) == 2:
                emit, region = regions
                map(*emit)
        else:
            map(*region)

        self.engine.mem_write(address, bytes(value))

        logger.debug(f"wrote {len(value)} bytes to 0x{address:x}")

    def load(self, code: state.Code) -> None:
        if code.base is None:
            raise ValueError(f"base address is required: {code}")

        self.write_memory(code.base, code.image)

        if code.entry is not None:
            self.entry = code.entry
            if self.entry < code.base or self.entry > code.base + len(code.image):
                raise ValueError(
                    "entry is not in code: 0x{self.entry:x} vs (0x{code.base:x}, 0x{code.base + len(code.image):x})"
                )
        else:
            self.entry = code.base

        self.bounds = code.bounds

        logger.info(f"loaded code (size: {len(code.image)} B) at 0x{code.base:x}")

    def hook(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        self.hooks[address] = function

        # Ensure that the address is mapped.
        try:
            self.engine.mem_map(
                (address // self.PAGE_SIZE) * self.PAGE_SIZE, self.PAGE_SIZE
            )
        except unicorn.UcError:
            pass

    def disassemble(
        self, code: bytes, base: int, count: typing.Optional[int] = None
    ) -> typing.Tuple[typing.List[capstone.CsInsn], str]:
        # TODO: annotate that offsets are relative.
        #
        # We don't know what the base address is at disassembly time - so we
        # just set it to 0. This means relative address arguments aren't
        # correctly calculated - we should annotate that relative arguments are
        # relative e.g., with a "+" or something.

        instructions = self.disassembler.disasm(code, base)

        disassembly = []
        insns = []
        for i, instruction in enumerate(instructions):
            if count is not None and i >= count:
                break
            insns.append(instruction)
            disassembly.append(f"{instruction.mnemonic} {instruction.op_str}")

        return (insns, "\n".join(disassembly))

    def current_instruction(self) -> capstone.CsInsn:
        pc = self.read_register("pc")
        code = self.read_memory(pc, 15)
        if code is None:
            raise AssertionError("invalid state")
        for i in self.disassembler.disasm(code, pc):
            return i

    @property
    def exit(self):
        for bound in self.bounds:
            if self.entry in bound:
                return bound.stop

        return None

    def check(self) -> None:
        if self.entry is None:
            raise exceptions.ConfigurationError(
                "no entry provided, emulation cannot start"
            )

        if not self.bounds:
            raise exceptions.ConfigurationError(
                "no bounds provided, emulation cannot start"
            )

        if self.exit is None:
            raise exceptions.ConfigurationError(
                "entry is not in valid execution bounds"
            )

    def run(self) -> None:
        self.check()

        logger.info(f"starting emulation at 0x{self.entry:x} until 0x{self.exit:x}")
        try:
            self.engine.emu_start(self.entry, self.exit)
        except unicorn.UcError as e:
            logger.warn(f"emulation stopped - reason: {e}")
            logger.warn("for more details, run emulation in single step mode")
            raise exceptions.EmulationError(e)

        logger.info("emulation complete")

    def step(self) -> bool:
        self.check()

        pc = self.read_register("pc")

        code = self.read_memory(pc, 15)  # longest possible instruction
        if code is None:
            assert False, "impossible state"
        (instr, disas) = self.disassemble(code, pc, 1)

        logger.info(f"single step at 0x{pc:x}: {disas}")

        try:
            self.engine.emu_start(pc, self.exit, count=1)
        except unicorn.UcError as e:
            logger.warn(f"emulation stopped - reason: {e}")
            self._error(e)

        pc = self.read_register("pc")

        for bound in self.bounds:
            if pc in bound:
                return False

        return True

    def _error(
        self, error: unicorn.UcError
    ) -> typing.Dict[typing.Union[str, int], typing.Union[int, bytes]]:
        """Raises new exception from unicorn exception with extra details.

        Should only be run while single stepping.

        Arguments:
            error: Unicorn exception.

        Raises:
            UnicornEmulationError with extra details about the error.
        """

        pc = self.read_register("pc")
        code = self.read_memory(pc, 16)

        if code is None:
            raise AssertionError("invalid state")

        insns, _ = self.disassemble(code, 1)
        i = instructions.Instruction.from_capstone(insns[0])

        if error.args[0] == unicorn.unicorn_const.UC_ERR_READ_UNMAPPED:
            details = {o.key(self): o.concretize(self) for o in i.reads}
        elif error.args[0] == unicorn.unicorn_const.UC_ERR_WRITE_UNMAPPED:
            details = {o.key(self): o.concretize(self) for o in i.writes}
        elif error.args[0] == unicorn.unicorn_const.UC_ERR_FETCH_UNMAPPED:
            details = {"pc": pc}
        elif error.args[0] == unicorn.unicorn_const.UC_ERR_INSN_INVALID:
            details = {"pc": pc, pc: code}

        raise exceptions.UnicornEmulationError(error.args[0], pc, details)

    def __repr__(self) -> str:
        return f"Unicorn(mode={self.mode}, arch={self.arch})"
