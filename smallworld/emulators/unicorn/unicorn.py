from __future__ import annotations

import logging
import sys
import typing
from enum import Enum

import capstone
import claripy
import unicorn
import unicorn.ppc_const  # Not properly exposed by the unicorn module

from ... import exceptions, instructions, platforms, utils
from .. import emulator, hookable
from .machdefs import UnicornMachineDef

logger = logging.getLogger(__name__)


class UnicornEmulationError(exceptions.EmulationError):
    def __init__(self, uc_err: unicorn.UcError, pc: int, msg: str, details: dict):
        self.uc_err = uc_err
        self.pc = pc
        self.msg = msg
        self.details = details

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}({self.uc_err}, {hex(self.pc)}, {self.details})"
        )


class UnicornEmulationMemoryReadError(UnicornEmulationError):
    pass


class UnicornEmulationMemoryWriteError(UnicornEmulationError):
    pass


class UnicornEmulationExecutionError(UnicornEmulationError):
    pass


class EmulatorState(Enum):
    START_BLOCK = 1
    START_STEP = 2
    STEP = 3
    BLOCK = 4
    RUN = 5
    SETUP = 6


class UnicornEmulator(
    emulator.Emulator,
    hookable.QInstructionHookable,
    hookable.QFunctionHookable,
    hookable.QMemoryReadHookable,
    hookable.QMemoryWriteHookable,
    hookable.QInterruptHookable,
):
    """An emulator for the Unicorn emulation engine."""

    description = "This is a smallworld class encapsulating the Unicorn emulator."
    name = "smallworld's-unicorn"
    version = "0.0"

    PAGE_SIZE = 0x1000

    def __init__(self, platform: platforms.Platform):
        super().__init__(platform)
        self.platform = platform
        self.machdef = UnicornMachineDef.for_platform(self.platform)
        self.engine = unicorn.Uc(self.machdef.uc_arch, self.machdef.uc_mode)
        self.disassembler = capstone.Cs(self.machdef.cs_arch, self.machdef.cs_mode)
        self.disassembler.detail = True

        self.memory_map: utils.RangeCollection = utils.RangeCollection()
        self.state: EmulatorState = EmulatorState.SETUP
        # labels are per byte

        # We'll have one entry in this dictionary per full-width base
        # register (by name) and those themselves are a map from offset
        # within the register to string label.
        # In other words, for 64-bit x86, we'd have
        # self.label["rax"][0] = "input", e.g., for the 0th byte in rax.
        # But we will not have self.label["eax"] -- you have to look in "rax"
        # Note that read_register_label will navigate that for you...
        # For memory, we have one label per byte in memory with address
        # translated via `hex(address)`.
        # In other words, self.label["0xdeadbeef"] = "came_from_hades" is
        # the label on that address in memory
        self.label: typing.Dict[str, typing.Dict[int, str]] = {}

        # this will run on *every instruction
        def code_callback(uc, address, size, user_data):
            # print(f"code callback addr={address:x}")
            # We want to end on the instruction after
            if self.state == EmulatorState.STEP:
                self.engine.emu_stop()
            if self.state == EmulatorState.START_STEP:
                self.state = EmulatorState.STEP

            if not self._bounds.is_empty() and not self._bounds.contains_value(address):
                self.engine.emu_stop()
                raise exceptions.EmulationBounds

            # check for if we've hit an exit point
            if address in self._exit_points:
                logger.debug(f"stopping emulation at exit point {address:x}")
                self.engine.emu_stop()
                raise exceptions.EmulationExitpoint

            # run instruciton hooks
            if self.all_instructions_hook:
                self.all_instructions_hook(self)

            if cb := self.is_instruction_hooked(address):
                logger.debug(f"hit hooking address for instruction at {address:x}")
                cb(self)
            # check function hooks *before* bounds since these might be out-of-bounds
            if cb := self.is_function_hooked(address):
                logger.debug(
                    f"hit hooking address for function at {address:x} -- {self.function_hooks[address]}"
                )
                # note that hooking a function means that we stop at function
                # entry and, after running the hook, we do not let the function
                # execute. Instead, we return from the function as if it ran.
                # this permits modeling
                # this is the model for the function
                cb(self)
                # self.engine.emu_stop()

                # Mimic a platform-specific "return" instruction.
                if self.platform.architecture == platforms.Architecture.X86_32:
                    # i386: pop a 4-byte value off the stack
                    sp = self.read_register("esp")
                    ret = int.from_bytes(
                        self.read_memory(sp, 4), self.platform.byteorder.value
                    )
                    self.write_register("esp", sp + 4)
                elif self.platform.architecture == platforms.Architecture.X86_64:
                    # amd64: pop an 8-byte value off the stack
                    sp = self.read_register("rsp")
                    ret = int.from_bytes(
                        self.read_memory(sp, 8), self.platform.byteorder.value
                    )
                    self.write_register("rsp", sp + 8)
                elif (
                    self.platform.architecture == platforms.Architecture.AARCH64
                    or self.platform.architecture == platforms.Architecture.ARM_V5T
                    or self.platform.architecture == platforms.Architecture.ARM_V6M
                    or self.platform.architecture
                    == platforms.Architecture.ARM_V6M_THUMB
                    or self.platform.architecture == platforms.Architecture.ARM_V7A
                    or self.platform.architecture == platforms.Architecture.ARM_V7M
                    or self.platform.architecture == platforms.Architecture.ARM_V7R
                    or self.platform.architecture == platforms.Architecture.POWERPC32
                    or self.platform.architecture == platforms.Architecture.POWERPC64
                ):
                    # aarch64, arm32, powerpc and powerpc64: branch to register 'lr'
                    ret = self.read_register("lr")
                elif (
                    self.platform.architecture == platforms.Architecture.MIPS32
                    or self.platform.architecture == platforms.Architecture.MIPS64
                ):
                    # mips32 and mips64: branch to register 'ra'
                    ret = self.read_register("ra")
                else:
                    raise exceptions.ConfigurationError(
                        "Don't know how to return for {self.platform.architecture}"
                    )

                self.write_register("pc", ret)

        self.engine.hook_add(unicorn.UC_HOOK_CODE, code_callback)

        # functions to run before memory read and write for
        # specific addresses

        def mem_read_callback(uc, type, address, size, value, user_data):
            assert type == unicorn.UC_MEM_READ
            orig_data = (value.to_bytes(size, self.platform.byteorder.value),)
            if self.all_reads_hook:
                data = self.all_reads_hook(self, address, size, orig_data)
                if data:
                    if len(data) != size:
                        raise exceptions.EmulationError(
                            f"Read hook at {hex(address)} returned {len(data)} bytes; need {size} bytes"
                        )
                    uc.mem_write(address, data)
                    orig_data = data

            if cb := self.is_memory_read_hooked(address):
                data = cb(self, address, size, orig_data)

                # Execute registered callback
                # data = cb(self, address, size)
                # Overwrite memory being read.
                # The instruction is emulated after this callback fires,
                # so the new value will get used for computation.
                if data:
                    if len(data) != size:
                        raise exceptions.EmulationError(
                            f"Read hook at {hex(address)} returned {len(data)} bytes; need {size} bytes"
                        )
                    uc.mem_write(address, data)

        def mem_write_callback(uc, type, address, size, value, user_data):
            assert type == unicorn.UC_MEM_WRITE
            if self.all_writes_hook:
                self.all_writes_hook(
                    self,
                    address,
                    size,
                    value.to_bytes(size, self.platform.byteorder.value),
                )

            if cb := self.is_memory_write_hooked(address):
                cb(
                    self,
                    address,
                    size,
                    value.to_bytes(size, self.platform.byteorder.value),
                )

        self.engine.hook_add(unicorn.UC_HOOK_MEM_WRITE, mem_write_callback)
        self.engine.hook_add(unicorn.UC_HOOK_MEM_READ, mem_read_callback)

        # function to run on *every* interrupt
        self.interrupts_hook: typing.Optional[
            typing.Callable[[emulator.Emulator, int], None]
        ] = None

        # function to run on a specific interrupt number
        self.interrupt_hook: typing.Dict[
            int, typing.Callable[[emulator.Emulator], None]
        ] = {}

        def interrupt_callback(uc, index, user_data):
            if self.interrupts_hook is not None:
                self.interrupts_hook()
            if index in self.interrupt_hook:
                self.interrupt_hook[index]()

        self.engine.hook_add(unicorn.UC_HOOK_INTR, interrupt_callback)

        def block_callback(uc, address, block_size, user_data):
            if self.state == EmulatorState.BLOCK:
                self.engine.emu_stop()
            if self.state == EmulatorState.START_BLOCK:
                self.state = EmulatorState.BLOCK

        self.engine.hook_add(unicorn.UC_HOOK_BLOCK, block_callback)

        # keep track of which registers have been initialized
        self.initialized_registers: typing.Dict[str, typing.Set[int]] = {}

    def _check_pc_ok(self, pc):
        """Check if this pc is ok to emulate, i.e. in bounds and not an exit
        point."""

        if not self._bounds.is_empty() and not self._bounds.contains_value(pc):
            # There are bounds, and we are not in them
            return False

        # check for if we've hit an exit point
        if pc in self._exit_points:
            logger.debug(f"stopping emulation at exit point {pc:x}")
            return False
        return True

    def _register(self, name: str) -> typing.Tuple[typing.Any, str, int, int]:
        # Translate register name into the tuple
        # (u, b, o, s)
        # u is the unicorn reg number
        # b is the name of full-width base register this is or is part of
        # o is start offset within full-width base register
        # s is size in bytes
        name = name.lower()
        # support some generic register references
        if name == "pc":
            name = self.machdef.pc_reg
        return self.machdef.uc_reg(name)

    def read_register_content(self, name: str) -> int:
        (reg, _, _, _) = self._register(name)
        if reg == 0:
            return 0
        # logger.warn(f"Unicorn doesn't support register {name} for {self.platform}")
        try:
            return self.engine.reg_read(reg)
        except Exception as e:
            raise exceptions.AnalysisError(f"Failed reading {name} (id: {reg})") from e

    def read_register_label(self, name: str) -> typing.Optional[str]:
        (_, base_reg, size, offset) = self._register(name)
        if base_reg in self.label:
            # we'll return a string repr of set of labels on all byte offsets
            # for this register
            labels = set([])
            for i in range(offset, offset + size):
                if i in self.label[base_reg]:
                    label = self.label[base_reg][i]
                    if label is not None:
                        labels.add(label)
            return ":".join(list(labels))
        return None

    def read_register(self, name: str) -> int:
        return self.read_register_content(name)

    def write_register_content(
        self, name: str, content: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        if content is None:
            logger.debug(f"ignoring register write to {name} - no value")
            return

        if isinstance(content, claripy.ast.bv.BV):
            raise exceptions.SymbolicValueError(
                "This emulator cannot handle bitvector expressions"
            )

        (reg, base_reg, size, start_offset) = self._register(name)
        try:
            self.engine.reg_write(reg, content)
        except Exception as e:
            raise exceptions.AnalysisError(f"Failed writing {name} (id: {reg})") from e
        # keep track of which bytes in this register have been initialized
        if base_reg not in self.initialized_registers:
            self.initialized_registers[base_reg] = set([])
        for o in range(start_offset, start_offset + size):
            self.initialized_registers[base_reg].add(o)
        logger.debug(f"set register {name}={content}")

    def write_register_label(
        self, name: str, label: typing.Optional[str] = None
    ) -> None:
        if label is None:
            return
        (_, base_reg, size, offset) = self._register(name)
        if base_reg not in self.label:
            self.label[base_reg] = {}
        for i in range(offset, offset + size):
            self.label[base_reg][i] = label

    def write_register(
        self, name: str, content: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        self.write_register_content(name, content)

    def read_memory_content(self, address: int, size: int) -> bytes:
        if size > sys.maxsize:
            raise ValueError(f"{size} is too large (max: {sys.maxsize})")
        try:
            return bytes(self.engine.mem_read(address, size))
        except unicorn.UcError as e:
            logger.warn(f"Unicorn raised an exception on memory read {e}")
            self._error(e, "mem")
            assert False  # Line is unreachable

    def read_memory_label(self, address: int, size: int) -> typing.Optional[str]:
        labels = set()
        if "mem" not in self.label:
            return None
        else:
            for a in range(address, address + size):
                if a in self.label["mem"]:
                    labels.add(self.label["mem"][a])
            if len(labels) == 0:
                return None
            return ":".join(list(labels))

    def read_memory(self, address: int, size: int) -> bytes:
        return self.read_memory_content(address, size)

    def map_memory(self, address: int, size: int) -> None:
        # Round address down to a page boundary
        page_address = (address // self.PAGE_SIZE) * self.PAGE_SIZE

        # Expand the size to accound for moving address
        page_size = size + address - page_address

        # Round page_size up to the next page
        page_size = (
            (page_size + self.PAGE_SIZE - 1) // self.PAGE_SIZE
        ) * self.PAGE_SIZE

        # Fill in any gaps in the specified region
        region = (page_address, page_address + page_size)
        missing_ranges = self.memory_map.get_missing_ranges(region)

        for start, end in missing_ranges:
            self.memory_map.add_range((start, end))
            self.engine.mem_map(start, end - start)

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        return list(self.memory_map.ranges)

    def _is_address_mapped(self, address):
        (ind, found) = self.memory_map.find_closest_range(address)
        return found

    def _is_address_range_mapped(self, address_range):
        (a, b) = address_range
        for address in range(a, b):
            if self._is_address_mapped(address) is False:
                return False
        return True

    def write_memory_content(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ) -> None:
        if content is None:
            raise ValueError(f"{self.__class__.__name__} requires concrete state")

        if isinstance(content, claripy.ast.bv.BV):
            raise exceptions.SymbolicValueError(
                "This emulator cannot handle bitvector expressions"
            )

        if len(content) > sys.maxsize:
            raise ValueError(f"{len(content)} is too large (max: {sys.maxsize})")

        if not len(content):
            raise ValueError("memory write cannot be empty")

        try:
            # print(f"write_memory: {content}")
            self.engine.mem_write(address, content)
        except unicorn.UcError as e:
            logger.warn(f"Unicorn raised an exception on memory write {e}")
            self._error(e, "mem")

        logger.debug(f"wrote {len(content)} bytes to 0x{address:x}")

    def write_memory_label(
        self, address: int, size: int, label: typing.Optional[str] = None
    ) -> None:
        if label is None:
            return
        if "mem" not in self.label:
            self.label["mem"] = dict()
        for a in range(address, address + size):
            self.label["mem"][a] = label

    def write_memory(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ) -> None:
        self.write_memory_content(address, content)

    def hook_instruction(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        super(UnicornEmulator, self).hook_instruction(address, function)
        self.map_memory(address, self.PAGE_SIZE)

    def hook_function(
        self, address: int, function: typing.Callable[[emulator.Emulator], None]
    ) -> None:
        super(UnicornEmulator, self).hook_function(address, function)
        self.map_memory(address, self.PAGE_SIZE)

    def _disassemble(
        self, code: bytes, base: int, count: typing.Optional[int] = None
    ) -> typing.Tuple[typing.List[capstone.CsInsn], str]:
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

    def _check(self) -> None:
        # check if it's ok to begin emulating
        # 1. pc must be set in order to emulate
        (_, base_name, size, offset) = self._register("pc")
        if (
            base_name in self.initialized_registers
            and len(self.initialized_registers[base_name]) == size
        ):
            # pc is fully initialized
            pass
        else:
            raise exceptions.ConfigurationError(
                "pc not initialized, emulation cannot start"
            )
        # 2. an exit point is also required
        if len(self._exit_points) == 0:
            raise exceptions.ConfigurationError(
                "at least one exit point must be set, emulation cannot start"
            )

    def step_instruction(self) -> None:
        self._check()
        self.state = EmulatorState.START_STEP

        pc = self.read_register("pc")
        exit_point = list(self._exit_points)[0]
        if pc == exit_point:
            raise exceptions.EmulationBounds

        if pc not in self.function_hooks:
            disas = self.current_instruction()
            logger.info(f"single step at 0x{pc:x}: {disas}")

        try:
            self.engine.emu_start(pc, exit_point)

        except unicorn.UcError as e:
            if (
                e.errno == unicorn.UC_ERR_FETCH_UNMAPPED
                and self.read_register("pc") in self.function_hooks
            ):
                # probably we tried to execute call to code that's not mapped?
                pass
            else:
                logger.warn(f"emulation stopped - reason: {e}")
                # translate this unicorn error into something richer
                self._error(e, "exec")

    def step_block(self) -> None:
        self._check()
        pc = self.read_register("pc")
        exit_point = list(self._exit_points)[0]

        disas = self.current_instruction()
        logger.info(f"step block at 0x{pc:x}: {disas}")
        try:
            self.state = EmulatorState.START_BLOCK
            self.engine.emu_start(pc, exit_point)
            pc = self.read_register("pc")

            self.state = EmulatorState.BLOCK
            self.engine.emu_start(pc, exit_point)
        except unicorn.UcError as e:
            logger.warn(f"emulation stopped - reason: {e}")
            logger.warn("for more details, run emulation in single step mode")

    def run(self) -> None:
        self._check()
        self.state = EmulatorState.RUN

        logger.info(
            f"starting emulation at 0x{self.read_register('pc'):x}"
        )  # until 0x{self._exit_point:x}")

        try:
            # unicorn requires one exit point so just use first
            exit_point = list(self._exit_points)[0]
            self.engine.emu_start(self.read_register("pc"), exit_point)
        except exceptions.EmulationStop:
            pass
        except unicorn.UcError as e:
            logger.warn(f"emulation stopped - reason: {e}")
            logger.warn("for more details, run emulation in single step mode")
            self._error(e, "exec")

        logger.info("emulation complete")

    def _error(
        self, error: unicorn.UcError, typ: str
    ) -> typing.Dict[typing.Union[str, int], typing.Union[str, int, bytes]]:
        """Raises new exception from unicorn exception with extra details.

        Should only be run while single stepping.

        Arguments:
            error: Unicorn exception.

        Raises:
            UnicornEmulationError with extra details about the error.
        """

        pc = self.read_register("pc")

        try:
            code = self.read_memory(pc, 16)
            insns, _ = self._disassemble(code, pc, 1)
            i = instructions.Instruction.from_capstone(insns[0])
        except:
            # looks like that code is not available
            i = None

        exc: typing.Type[exceptions.EmulationError] = exceptions.EmulationError

        if typ == "mem":
            prefix = "Failed memory access"
            exc = UnicornEmulationMemoryReadError
        if typ == "exec":
            prefix = "Quit emulation"
            exc = UnicornEmulationExecutionError
        else:
            prefix = "Unexpected Unicorn error"

        # rws is list of either reads or writes. get list of these
        # reads or writes that is not actually available, i.e. memory
        # not mapped
        def get_unavailable_rw(rws):
            out = []
            for rw in rws:
                if type(rw) is instructions.BSIDMemoryReferenceOperand:
                    a = rw.address(self)
                    if not (self._is_address_mapped(a)):
                        out.append((rw, a))
            return out

        details: typing.Dict[typing.Union[str, int], typing.Union[str, int, bytes]] = {}

        def details_str(details):
            for k, v in details.items():
                if k == "pc":
                    return f" pc=0x{pc:x}"
                if "_reads" in k or "_writes" in k:
                    s = ""
                    for rw, a in v:
                        rws = str(rw)
                        import re

                        foo = re.search(r"\((.*)\)$", rws)
                        rw = foo.groups()[0]
                        x = f"address=0x{a:x} i.e. [{rw}]"
                        if s == "":
                            s = x
                        else:
                            s = s + ", " + x
                    return s

        if error.errno == unicorn.UC_ERR_READ_UNMAPPED:
            msg = f"{prefix} due to read of unmapped memory"
            # actually this is a memory read error
            exc = UnicornEmulationMemoryReadError
            details["unmapped_reads"] = get_unavailable_rw(i.reads)
        elif error.errno == unicorn.UC_ERR_READ_PROT:
            msg = f"{prefix} due to read of mapped but protected memory"
            # actually this is a memory read error
            exc = UnicornEmulationMemoryReadError
            details["protected_reads"] = get_unavailable_rw(i.reads)
        elif error.errno == unicorn.UC_ERR_READ_UNALIGNED:
            msg = f"{prefix} due to unaligned read"
            # actually this is a memory read error
            exc = UnicornEmulationMemoryReadError
            details["unaligned_reads"] = get_unavailable_rw(i.reads)

        elif error.errno == unicorn.UC_ERR_WRITE_UNMAPPED:
            msg = f"{prefix} due to write to unmapped memory"
            # actually this is a memory write error
            exc = UnicornEmulationMemoryWriteError
            details["unmapped_writes"] = get_unavailable_rw(i.writes)
        elif error.errno == unicorn.UC_ERR_WRITE_PROT:
            msg = f"{prefix} due to write to mapped but protected memory"
            # actually this is a memory write error
            exc = UnicornEmulationMemoryWriteError
            details["protected_writes"] = get_unavailable_rw(i.writes)
        elif error.errno == unicorn.UC_ERR_WRITE_UNALIGNED:
            msg = f"{prefix} due to unaligned write"
            # actually this is a memory write error
            exc = UnicornEmulationMemoryWriteError
            details["unaligned_writes"] = get_unavailable_rw(i.writes)

        elif error.errno == unicorn.UC_ERR_FETCH_UNMAPPED:
            msg = f"{prefix} due to fetch of unmapped memory"
        elif error.errno == unicorn.UC_ERR_FETCH_PROT:
            msg = f"{prefix} due to fetch of from mapped but protected memory"
        elif error.errno == unicorn.UC_ERR_FETCH_UNALIGNED:
            msg = f"{prefix} due to unaligned fetch"

        elif error.errno == unicorn.UC_ERR_NOMEM:
            msg = f"{prefix} due Out-Of-Memory"
        elif error.errno == unicorn.UC_ERR_INSN_INVALID:
            msg = f"{prefix} due invalid instruction"
            details = {"pc": pc, "instr": str(i)}
        elif error.errno == unicorn.UC_ERR_RESOURCE:
            msg = f"{prefix} due insufficient resources"
        elif error.errno == unicorn.UC_ERR_EXCEPTION:
            msg = f"{prefix} due cpu exception"
        else:
            msg = f"{prefix} due to unknown Unicorn error {error.errno}"

        raise exc(error, pc, msg + " " + details_str(details), details)

    def __repr__(self) -> str:
        return f"UnicornEmulator(platform={self.platform})"


__all__ = [
    "UnicornEmulator",
    "UnicornEmulationMemoryReadError",
    "UnicornEmulationMemoryWriteError",
    "UnicornEmulationExecutionError",
]
