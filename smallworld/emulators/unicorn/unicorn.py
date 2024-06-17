from __future__ import annotations

import logging
import sys
import typing

import capstone
import unicorn
import unicorn.ppc_const  # Not properly exposed by the unicorn module

from ... import exceptions, instructions, state
from .. import emulator
from .machdefs import UnicornMachineDef

logger = logging.getLogger(__name__)


class UnicornEmulator(emulator.Emulator):
    """An emulator for the Unicorn emulation engine.

    Arguments:
        arch: Architecture ID string
        mode: Mode ID string
        byteorder: Byteorder

    """

    PAGE_SIZE = 0x1000

    def __init__(self, arch: str, mode: str, byteorder: str):
        super().__init__()
        self.arch = arch
        self.mode = mode
        self.byteorder = byteorder

        self.machdef = UnicornMachineDef.for_arch(arch, mode, byteorder)

        self.entry: typing.Optional[int] = None

        self.engine = unicorn.Uc(self.machdef.uc_arch, self.machdef.uc_mode)

        self.disassembler = capstone.Cs(self.machdef.cs_arch, self.machdef.cs_mode)
        self.disassembler.detail = True
        self.bounds: typing.Iterable[range] = []

        self.hooks: typing.Dict[
            int, typing.Tuple[typing.Callable[[emulator.Emulator], None], bool]
        ] = {}
        self.hook_return = None

        def callback(uc, address, size, user_data):
            if address in self.hooks:
                logger.debug(f"hit hooking address {address:x}")
                hook, finish = self.hooks[address]

                hook(self)

                if finish:
                    if self.hook_return is None:
                        raise RuntimeError("return point unknown")
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
            name = self.machdef.pc_reg

        res = self.machdef.uc_reg(name)
        return res

    def read_register(self, name: str) -> int:
        reg = self.register(name)
        if reg == 0:
            logger.warn(
                f"Unicorn doesn't support register {name} for {self.arch}:{self.mode}:{self.byteorder}"
            )
        return self.engine.reg_read(self.register(name))

    def write_register(self, name: str, value: typing.Optional[int]) -> None:
        if value is None:
            logger.debug(f"ignoring register write to {name} - no value")
            return

        self.engine.reg_write(self.register(name), value)

        logger.debug(f"set register {name}={value}")

    def get_pages(self, num_pages: int) -> int:
        last_page = 0
        # iterate over pages emulator has mapped and determine last page
        for start, end, perms in self.engine.mem_regions():
            # Assume "end" is last byte in page and figure out what
            # page it's in
            end_page = (end // self.PAGE_SIZE) * self.PAGE_SIZE
            if end_page > last_page:
                last_page = end_page
        next_page = last_page + self.PAGE_SIZE
        self.engine.mem_map(next_page, num_pages * self.PAGE_SIZE)
        return next_page

    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        if size > sys.maxsize:
            raise ValueError(f"{size} is too large (max: {sys.maxsize})")

        try:
            return self.engine.mem_read(address, size)
        except unicorn.unicorn.UcError:
            logger.warn(f"attempted to read uninitialized memory at 0x{address:x}")
            return None

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
        self,
        address: int,
        function: typing.Callable[[emulator.Emulator], None],
        finish: bool = False,
    ) -> None:
        self.hooks[address] = (function, finish)

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

        for entry in self.hooks.keys():
            if pc == entry:
                return False

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
