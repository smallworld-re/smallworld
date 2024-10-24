from __future__ import annotations

import logging
import sys
import typing

import capstone
import unicorn
import unicorn.ppc_const  # Not properly exposed by the unicorn module

from ... import exceptions, platforms, utils
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


class UnicornEmulationMemoryError(UnicornEmulationError):
    pass


class UnicornEmulationExecutionError(UnicornEmulationError):
    pass


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

        # NB: instruction, function, memory read and write, and interrupt hook
        # data (what to hook and function to run) are provided by
        # `UnicornInstructionHookable` inheritance etc.
        # this is used to be able to "return" from a function without running it
        self.hook_return = None

        # list of exit points which will end emulation
        # self.exit_points = []

        # this will run on *every instruction
        def code_callback(uc, address, size, user_data):
            # if address == 0x3800:
            #    import pdb
            #    pdb.set_trace()

            print(f"code callback addr={address:x}")
            if not self._bounds.is_empty():
                # check that we are in bounds
                if self._bounds.find_range(address) is None:
                    # not in bounds for any of the ranges specified
                    print("boudns?")

                    if (
                        self.emulation_in_progress == STEP_BLOCK
                        or self.emulation_in_progress == RUN
                    ):
                        self.engine.emu_stop()
                    raise exceptions.EmulationBounds

            # check for if we've hit an exit point
            if address in self._exit_points:
                logger.debug(f"stopping emulation at exit point {address:x}")
                self.engine.emu_stop()
                raise exceptions.EmulationExitpoint
            # run instruciton hooks
            if self.all_instructions_hook:
                print("here")
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
                if self.hook_return is None:
                    raise RuntimeError("return point for function hook is unknown")
                self.write_register("pc", self.hook_return)
            # this is always keeping track of *next* instruction which, would be
            # return addr for a call.
            self.hook_return = address + size

        self.engine.hook_add(unicorn.UC_HOOK_CODE, code_callback)

        # functions to run before memory read and write for
        # specific addresses

        def mem_read_callback(uc, type, address, size, value, user_data):
            assert type == unicorn.UC_MEM_READ
            if self.memory_read_hooks:
                if self.all_reads_hook:
                    data = self.manager.all_reads_hook(self, address, size)

                if cb := self.is_memory_read_hooked(address):
                    data = cb(self, address, size)

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
            for seg, cb in self.memory_write_hooks.items():
                if address in seg:
                    cb(
                        self,
                        address,
                        size,
                        value.to_bytes(size, self.platform.byteorder.value),
                    )
                    break

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

        # controls how we step: by block or by instruction
        self.stepping_by_block = False

        # this callback is used to manage `step_block` I guess
        def block_callback(uc, address, block_size, user_data):
            if self.stepping_by_block:
                self.engine.emu_stop()

        # keep track of which registers have been initialized
        self.initialized_registers: typing.Dict[str, typing.Set[int]] = {}

    def _check_pc_ok(self, pc):
        """Check if this pc is ok to emulate, i.e. in bounds and not an exit
        point."""

        if not self._bounds.is_empty and self._bounds.find_range(pc) is None:
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
            logger.warn(f"Unicorn doesn't support register {name} for {self.platform}")
        try:
            return self.engine.reg_read(reg)
        except:
            raise exceptions.AnalysisError(f"Failed reading {name} (id: {reg})")

    def read_register_type(self, name: str) -> typing.Optional[typing.Any]:
        # not supported yet
        return None

    def read_register_label(self, name: str) -> typing.Optional[str]:
        (_, base_reg, offset, size) = self._register(name)
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

    def write_register_content(self, name: str, content: typing.Optional[int]) -> None:
        if content is None:
            logger.debug(f"ignoring register write to {name} - no value")
            return
        #        import pdb
        #        pdb.set_trace()
        (reg, base_reg, offset, size) = self._register(name)
        self.engine.reg_write(reg, content)
        # keep track of which bytes in this register have been initialized
        if base_reg not in self.initialized_registers:
            self.initialized_registers[base_reg] = set([])
        for o in range(offset, offset + size):
            self.initialized_registers[base_reg].add(o)
        logger.debug(f"set register {name}={content}")

    def write_register_type(
        self, name: str, typ: typing.Optional[typing.Any] = None
    ) -> None:
        # not supported yet
        pass

    def write_register_label(
        self, name: str, label: typing.Optional[str] = None
    ) -> None:
        if label is None:
            return
        (_, base_reg, offset, size) = self._register(name)
        if base_reg not in self.label:
            self.label[base_reg] = {}
        for i in range(offset, offset + size):
            self.label[base_reg][i] = label

    def write_register(self, name: str, content: int) -> None:
        self.write_register_content(name, content)

    def read_memory_content(self, address: int, size: int) -> bytes:
        if size > sys.maxsize:
            raise ValueError(f"{size} is too large (max: {sys.maxsize})")
        try:
            return self.engine.mem_read(address, size)
        except unicorn.UcError as e:
            logger.warn(f"Unicorn raised an exception on memory read {e}")
            self._error(e, "mem")
            assert False  # Line is unreachable

    def read_memory_type(self, address: int, size: int) -> typing.Optional[typing.Any]:
        # not supported yet
        return None

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

    def write_memory_content(self, address: int, content: bytes) -> None:
        if content is None:
            raise ValueError(f"{self.__class__.__name__} requires concrete state")

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

    def write_memory_type(
        self, address: int, size: int, type: typing.Optional[typing.Any] = None
    ) -> None:
        # not supported yet
        pass

    def write_memory_label(
        self, address: int, size: int, label: typing.Optional[str] = None
    ) -> None:
        if label is None:
            return
        if "mem" not in self.label:
            self.label["mem"] = dict()
        for a in range(address, address + size):
            self.label["mem"][a] = label

    def write_memory(self, address: int, content: bytes) -> None:
        self.write_memory_content(address, content)

    def disassemble(
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
        (_, base_name, offset, size) = self._register("pc")
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

    def _step(self, by_block: bool = False) -> None:
        self._check()

        # by_block == True means stepping by a basic block at a time
        # by_block == False means stepping by instruction
        self.stepping_by_block = by_block

        pc = self.read_register("pc")

        try:
            # NB: unicorn requires an exit point so just use first in our
            # list. Note that we still check all of them at each instruction in
            # code callback
            if by_block:
                # stepping by block -- just start emulating and the block
                # callback will end emulation when we hit next bb
                # Note: assuming no block will be longer than 1000 instructions
                logger.info(f"block step at 0x{pc:x}")
                exit_point = list(self._exit_points)[0]
                self.engine.emu_start(pc, exit_point, count=1000)
            else:
                # stepping by instruction
                exit_point = list(self._exit_points)[0]
                if pc == exit_point:
                    raise exceptions.EmulationBounds
                if pc in self.function_hooks:
                    pass
                else:
                    code = self.read_memory(pc, 15)  # longest possible instruction
                    if code is None:
                        assert False, "impossible state"
                    (instr, disas) = self.disassemble(code, pc, 1)
                    logger.info(f"single step at 0x{pc:x}: {disas}")

                self.engine.emu_start(pc, exit_point, count=1)

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

    def step_instruction(self) -> None:
        self._step()

    def step_block(self) -> None:
        self._step(by_block=True)

    def run(self) -> None:
        self._check()

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
    ) -> typing.Dict[typing.Union[str, int], typing.Union[int, bytes]]:
        """Raises new exception from unicorn exception with extra details.

        Should only be run while single stepping.

        Arguments:
            error: Unicorn exception.

        Raises:
            UnicornEmulationError with extra details about the error.
        """

        pc = self.read_register("pc")
        # TODO: If the PC is unmapped, this will cause an infinite loop.
        # We can turn this back on when we can detect unmapped addresses.
        # code = self.read_memory(pc, 16)

        # insns, _ = self.disassemble(code, 1)
        #        i = instructions.Instruction.from_capstone(insns[0])
        code = b""

        exc: typing.Type[exceptions.EmulationError] = exceptions.EmulationError

        if typ == "mem":
            prefix = "Failed memory access"
            exc = UnicornEmulationMemoryError
        elif typ == "exec":
            prefix = "Quit emulation"
            exc = UnicornEmulationExecutionError
        else:
            prefix = "Unexpected Unicorn error"

        details: typing.Dict[typing.Union[str, int], typing.Union[int, bytes]] = {}
        if error.errno == unicorn.UC_ERR_READ_UNMAPPED:
            msg = f"{prefix} due to read of unmapped memory"
            # details = {o.key(self): o.concretize(self) for o in i.reads}
        elif error.errno == unicorn.UC_ERR_WRITE_UNMAPPED:
            msg = f"{prefix} due to write to unmapped memory"
            # details = {o.key(self): o.concretize(self) for o in i.writes}
        elif error.errno == unicorn.UC_ERR_FETCH_UNMAPPED:
            msg = f"{prefix} due to fetch of unmapped memory"
            details = {"pc": pc}
        elif error.errno == unicorn.UC_ERR_READ_PROT:
            msg = f"{prefix} due to read of mapped but protected memory"
            # details = {o.key(self): o.concretize(self) for o in i.reads}
        elif error.errno == unicorn.UC_ERR_WRITE_PROT:
            msg = f"{prefix} due to write to mapped but protected memory"
            # details = {o.key(self): o.concretize(self) for o in i.writes}
        elif error.errno == unicorn.UC_ERR_FETCH_PROT:
            msg = f"{prefix} due to fetch of from mapped but protected memory"
            details = {"pc": pc}
        elif error.errno == unicorn.UC_ERR_READ_UNALIGNED:
            msg = f"{prefix} due to unaligned read"
            # details = {o.key(self): o.concretize(self) for o in i.reads}
        elif error.errno == unicorn.UC_ERR_WRITE_UNALIGNED:
            msg = f"{prefix} due to unaligned write"
            # details = {o.key(self): o.concretize(self) for o in i.writes}
        elif error.errno == unicorn.UC_ERR_FETCH_UNALIGNED:
            msg = f"{prefix} due to unaligned fetch"
            details = {"pc": pc}
        elif error.errno == unicorn.UC_ERR_NOMEM:
            msg = f"{prefix} due Out-Of-Memory"
            details = {"pc": pc}
        elif error.errno == unicorn.UC_ERR_INSN_INVALID:
            msg = f"{prefix} due invalid instruction"
            details = {"pc": pc, f"{hex(pc)}": code}
        elif error.errno == unicorn.UC_ERR_RESOURCE:
            msg = f"{prefix} due insufficient resources"
            details = {"pc": pc}
        elif error.errno == unicorn.UC_ERR_EXCEPTION:
            msg = f"{prefix} due cpu exception"
            details = {"pc": pc}
        else:
            msg = f"{prefix} due to unknown Unicorn error {error.errno}"

        raise exc(error, pc, msg, details)

    def __repr__(self) -> str:
        return f"UnicornEmulator(platform={self.platform})"
