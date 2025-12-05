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


class UnicornEmulationMemoryFetchError(UnicornEmulationError):
    pass


class UnicornEmulationMemoryReadError(UnicornEmulationError):
    pass


class UnicornEmulationMemoryWriteError(UnicornEmulationError):
    pass


class UnicornEmulationExecutionError(UnicornEmulationError):
    pass


class EmulatorState(Enum):
    START_BLOCK = 1
    START_STEP = 2
    DELAY_STEP = 3
    STEP = 4
    BLOCK = 5
    RUN = 6
    SETUP = 7
    EXIT = 8


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
        self.platdef = platforms.PlatformDef.for_platform(self.platform)
        self.machdef = UnicornMachineDef.for_platform(self.platform)
        self.engine = unicorn.Uc(self.machdef.uc_arch, self.machdef.uc_mode)
        self.disassembler = capstone.Cs(
            self.platdef.capstone_arch, self.platdef.capstone_mode
        )
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
            # Check if we're out of bounds
            if not self._bounds.is_empty() and not self._bounds.contains_value(address):
                self.state = EmulatorState.EXIT
                self.engine.emu_stop()
                raise exceptions.EmulationBounds

            # check for if we've hit an exit point
            if address in self._exit_points:
                logger.debug(f"stopping emulation at exit point {address:x}")
                self.state = EmulatorState.EXIT
                self.engine.emu_stop()
                raise exceptions.EmulationExitpoint

            # Check single-step conditions.
            #
            # This callback gets invoked before the instruction is emulated.
            # When single-stepping, we want to run through it once,
            # and then stop emulation when it's run the second time.
            #
            # NOTE: Calling emu_stop() doesn't immediately stop emulation.
            # Returning here prevents spurious instruction and function hooks.
            # The memory read/write hooks also check for EXIT
            # to ensure they don't get called twice on the same event.
            if self.state == EmulatorState.STEP:
                self.state = EmulatorState.EXIT
                self.engine.emu_stop()
                return
            if self.state == EmulatorState.DELAY_STEP:
                self.state = EmulatorState.STEP
            if self.state == EmulatorState.START_STEP:
                insn = self.current_instruction()
                if insn.mnemonic in self.platdef.delay_slot_mnemonics:
                    self.state = EmulatorState.DELAY_STEP
                else:
                    self.state = EmulatorState.STEP

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

        self.engine.hook_add(unicorn.UC_HOOK_CODE, code_callback)

        # functions to run before memory read and write for
        # specific addresses

        def mem_read_callback(uc, type, address, size, value, user_data):
            assert type == unicorn.UC_MEM_READ

            if self.state == EmulatorState.EXIT:
                # Spurious call during the end of a single-step
                #
                # It looks like the emulator may continue processing an instruction
                # even after emu_stop() is called.
                return

            orig_data = value.to_bytes(size, self.platform.byteorder.value)
            if self.all_reads_hook:
                data = self.all_reads_hook(self, address, size, orig_data)
                if data:
                    if len(data) != size:
                        raise exceptions.EmulationError(
                            f"Read hook at {hex(address)} returned {len(data)} bytes; need {size} bytes"
                        )
                    uc.mem_write(address, data)
                    orig_data = data

            if cb := self.is_memory_read_hooked(address, size):
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

            if self.state == EmulatorState.EXIT:
                # Spurious call during the end of a single-step
                #
                # It looks like the emulator may continue processing an instruction
                # even after emu_stop() is called.
                return

            if self.all_writes_hook:
                self.all_writes_hook(
                    self,
                    address,
                    size,
                    value.to_bytes(size, self.platform.byteorder.value),
                )

            if cb := self.is_memory_write_hooked(address, size):
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
                if address != self.read_register("pc"):
                    # If a THUMB block jumps to an ARM block,
                    # the reported PC will be the address of the jump,
                    # not the address of the current block.
                    # The rest of the registers behave as if the jump had happened.
                    # On arm32, this includes flipping execution modes on a `blx` instruction.
                    #
                    # Manually updating PC from the address supplied
                    # in this callback fixes the problem.
                    self.write_register("pc", address)
                self.state = EmulatorState.EXIT
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

    def _register(self, name: str) -> typing.Tuple[typing.Any, str, int, int, bool]:
        # Translate register name into the tuple
        # (u, b, o, s, is_msr)
        # u is the unicorn reg number
        # b is the name of full-width base register this is or is part of
        # o is start offset within full-width base register
        # s is size in bytes
        # is_msr will be true if this is a model-specific reg, in which case u will be the id for that
        name = name.lower()
        # support some generic register references
        if name == "pc":
            name = self.platdef.pc_register

        is_msr = (name == "fsbase") or (name == "gsbase")
        uc_const = self.machdef.uc_reg(name)
        reg = self.platdef.registers[name]

        if hasattr(reg, "parent"):
            parent = reg.parent
            offset = reg.offset
        else:
            parent = reg.name
            offset = 0

        return (uc_const, parent, reg.size, offset, is_msr)

    def read_register_content(self, name: str) -> int:
        (reg, _, _, _, is_msr) = self._register(name)
        if reg == 0:
            raise exceptions.UnsupportedRegisterError(
                "Unicorn does not support register {name} for {self.platform}"
            )
        try:
            if is_msr:
                return self.engine.msr_read(reg)
            else:
                return self.engine.reg_read(reg)
        except Exception as e:
            raise exceptions.AnalysisError(f"Failed reading {name} (id: {reg})") from e

    def read_register_label(self, name: str) -> typing.Optional[str]:
        (_, base_reg, size, offset, _) = self._register(name)
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

        if name == "pc":
            content = self._handle_thumb_interwork(content)

        (reg, base_reg, size, start_offset, is_msr) = self._register(name)
        try:
            if is_msr:
                self.engine.msr_write(reg, content)
            else:
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
        (_, base_reg, size, offset, _) = self._register(name)
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
        (_, base_name, size, offset, _) = self._register("pc")
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
        # 2. an exit point or bound is also required
        if len(self._exit_points) == 0 and self._bounds.is_empty():
            raise exceptions.ConfigurationError(
                "at least one exit point or bound must be set, emulation cannot start"
            )

    def _check_arm32_platform(self):
        """Check for ARM32 platform architecture"""
        return self.platform.architecture in [
            platforms.Architecture.ARM_V5T,
            platforms.Architecture.ARM_V6M,
            platforms.Architecture.ARM_V7A,
            platforms.Architecture.ARM_V7M,
            platforms.Architecture.ARM_V7R,
        ]

    def get_thumb(self) -> bool:
        if not self._check_arm32_platform():
            raise exceptions.ConfigurationError(
                "called get_thumb() on non-ARM32 system"
            )

        CPSR_THUMB_MODE_MASK = 0x20
        cpsr = self.engine.reg_read(unicorn.arm_const.UC_ARM_REG_CPSR)
        if cpsr & CPSR_THUMB_MODE_MASK:
            return True
        else:
            return False

    def set_thumb(self, enabled=True) -> None:
        if not self._check_arm32_platform():
            raise exceptions.ConfigurationError(
                "called set_thumb() on non-ARM32 system"
            )

        CPSR_THUMB_MODE_MASK = 0x20
        cpsr = self.engine.reg_read(unicorn.arm_const.UC_ARM_REG_CPSR)

        if enabled:
            self.engine.reg_write(
                unicorn.arm_const.UC_ARM_REG_CPSR, cpsr | CPSR_THUMB_MODE_MASK
            )
        elif cpsr & CPSR_THUMB_MODE_MASK:
            self.engine.reg_write(
                unicorn.arm_const.UC_ARM_REG_CPSR, cpsr ^ CPSR_THUMB_MODE_MASK
            )

    # Handle Thumb ISA exchange for ARM32
    def _handle_thumb_interwork(self, pc) -> int:
        if not self._check_arm32_platform():
            return pc

        # emu_start clears thumb mode if the low bit of pc != 1.
        # We use CPSR to determine if unicorn was previously in thumb
        # mode and set the low bit to 1 to maintain it. We also set
        # the mode of the disassembler.
        if self.get_thumb() or pc & 1:
            pc |= 1
            self.disassembler.mode = capstone.CS_MODE_THUMB
        else:
            self.disassembler.mode = capstone.CS_MODE_ARM

        return pc

    def step_instruction(self) -> None:
        self._check()
        self.state = EmulatorState.START_STEP

        pc = self.read_register("pc")
        if pc in self._exit_points:
            raise exceptions.EmulationExitpoint

        pc = self._handle_thumb_interwork(pc)

        if pc not in self.function_hooks and self.memory_map.contains_value(pc):
            disas = self.current_instruction()
            logger.debug(f"single step at 0x{disas.address:x}: {disas}")

        try:
            self.engine.emu_start(pc, 0x0)

        except unicorn.UcError as e:
            if (
                e.errno == unicorn.UC_ERR_FETCH_UNMAPPED
                and self.read_register("pc") in self.function_hooks
            ):
                # probably we tried to execute call to code that's not mapped?
                pass
            else:
                # translate this unicorn error into something richer
                self._error(e, "exec")

    def step_block(self) -> None:
        self._check()
        pc = self.read_register("pc")
        pc = self._handle_thumb_interwork(pc)
        if pc in self._exit_points:
            raise exceptions.EmulationExitpoint

        disas = self.current_instruction()
        logger.info(f"step block at 0x{disas.address:x}: {disas}")
        try:
            self.state = EmulatorState.START_BLOCK
            self.engine.emu_start(pc, 0x0)

            self.state = EmulatorState.BLOCK
            pc = self.read_register("pc")
            pc = self._handle_thumb_interwork(pc)
            self.engine.emu_start(pc, 0x0)
        except unicorn.UcError as e:
            self._error(e, "exec")

    def run(self) -> None:
        self._check()
        self.state = EmulatorState.RUN

        logger.info(
            f"starting emulation at 0x{self.read_register('pc'):x}"
        )  # until 0x{self._exit_point:x}")

        try:
            pc = self.read_register("pc")
            pc = self._handle_thumb_interwork(pc)
            self.engine.emu_start(pc, 0x0)
        except exceptions.EmulationStop:
            pass
        except unicorn.UcError as e:
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
            # NB: can't use self.read_memory here since if it has an exception it will call _error, itself.
            code = bytes(self.engine.mem_read(pc, 16))
            # on arm32, update disassembler for ARM vs Thumb
            _ = self._handle_thumb_interwork(pc)
            insns, _ = self._disassemble(code, pc, 1)
            i = instructions.Instruction.from_capstone(insns[0])
        except:
            # looks like that code is not available
            i = None

        exc: exceptions.EmulationError = exceptions.EmulationError(
            "Completely unknown Unicorn error"
        )
        operands: typing.List[typing.Any] = []

        if typ == "mem":
            prefix = "Failed memory access"
        if typ == "exec":
            prefix = "Quit emulation"
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
            return "None"

        if error.errno == unicorn.UC_ERR_READ_UNMAPPED:
            msg = f"{prefix} due to read of unmapped memory"
            # actually this is a memory read error
            if i is not None:
                operands = get_unavailable_rw(i.reads)
            exc = exceptions.EmulationReadUnmappedFailure(msg, pc, operands=operands)

        elif error.errno == unicorn.UC_ERR_READ_PROT:
            msg = f"{prefix} due to read of mapped but protected memory"
            # actually this is a memory read error
            if i is not None:
                operands = get_unavailable_rw(i.reads)
            exc = exceptions.EmulationReadProtectedFailure(msg, pc, operands=operands)

        elif error.errno == unicorn.UC_ERR_READ_UNALIGNED:
            msg = f"{prefix} due to unaligned read"
            # actually this is a memory read error
            if i is not None:
                operands = get_unavailable_rw(i.reads)
            exc = exceptions.EmulationReadUnalignedFailure(msg, pc, operands=operands)

        elif error.errno == unicorn.UC_ERR_WRITE_UNMAPPED:
            msg = f"{prefix} due to write to unmapped memory"
            # actually this is a memory write error
            if i is not None:
                operands = get_unavailable_rw(i.writes)
            exc = exceptions.EmulationWriteUnmappedFailure(msg, pc, operands=operands)

        elif error.errno == unicorn.UC_ERR_WRITE_PROT:
            msg = f"{prefix} due to write to mapped but protected memory"
            # actually this is a memory write error
            if i is not None:
                operands = get_unavailable_rw(i.writes)
            exc = exceptions.EmulationWriteProtectedFailure(msg, pc, operands=operands)

        elif error.errno == unicorn.UC_ERR_WRITE_UNALIGNED:
            msg = f"{prefix} due to unaligned write"
            # actually this is a memory write error
            if i is not None:
                operands = get_unavailable_rw(i.writes)
            exc = exceptions.EmulationWriteUnalignedFailure(msg, pc, operands=operands)

        elif error.errno == unicorn.UC_ERR_FETCH_UNMAPPED:
            msg = f"{prefix} due to fetch of unmapped memory at"
            if pc in self._exit_points:
                raise exceptions.EmulationExitpoint
            if not self._bounds.is_empty() and not self._bounds.contains_value(pc):
                # This is actually an out-of-bounds error
                raise exceptions.EmulationBounds
            exc = exceptions.EmulationFetchUnmappedFailure(msg, pc, address=pc)

        elif error.errno == unicorn.UC_ERR_FETCH_PROT:
            msg = f"{prefix} due to fetch of from mapped but protected memory"
            exc = exceptions.EmulationFetchProtectedFailure(msg, pc, address=pc)

        elif error.errno == unicorn.UC_ERR_FETCH_UNALIGNED:
            msg = f"{prefix} due to unaligned fetch"
            exc = exceptions.EmulationFetchUnalignedFailure(msg, pc, address=pc)

        elif error.errno == unicorn.UC_ERR_NOMEM:
            msg = f"{prefix} due Out-Of-Memory"
            exc = exceptions.EmulationError(msg)

        elif error.errno == unicorn.UC_ERR_INSN_INVALID:
            msg = f"{prefix} due invalid instruction"
            exc = exceptions.EmulationExecInvalidFailure(msg, pc, i)

        elif error.errno == unicorn.UC_ERR_RESOURCE:
            msg = f"{prefix} due insufficient resources"
            exc = exceptions.EmulationError(msg)

        elif error.errno == unicorn.UC_ERR_EXCEPTION:
            msg = f"{prefix} due cpu exception"
            exc = exceptions.EmulationError(msg)

        else:
            msg = f"{prefix} due to unknown Unicorn error {error.errno}"
            exc = exceptions.EmulationError(msg)

        logger.warn(f"emulation stopped - reason: {error}")

        if i is None:
            logger.warn(
                f"FYI Unicorn rich exception processing unable to read code at pc=0x{pc:x} bc it is unavailable"
            )
        raise exc from error

    def __repr__(self) -> str:
        return f"UnicornEmulator(platform={self.platform})"


__all__ = [
    "UnicornEmulator",
    "UnicornEmulationMemoryReadError",
    "UnicornEmulationMemoryWriteError",
    "UnicornEmulationExecutionError",
]
