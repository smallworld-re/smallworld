import logging
import typing

import claripy
import jpype
from ghidra.pcode.emu import PcodeEmulator, PcodeThread
from ghidra.pcode.exec import PcodeExecutorStatePiece
from ghidra.program.model.address import AddressRangeImpl
from ghidra.program.model.pcode import Varnode

from ... import exceptions, platforms, utils
from ..emulator import Emulator
from .machdefs import GhidraMachineDef
from .typing import AbstractGhidraEmulator

log = logging.getLogger(__name__)


class GhidraEmulator(AbstractGhidraEmulator):
    name = "pcode-emulator"
    description = "Emulator based on pyghidra and pcode"
    version = "0.0.1"

    # Convert bytes into a JPype byte[]
    # bytes and bytearray are considered variants of String by JPype
    bytes_py_to_java = jpype.JByte[:]

    @staticmethod
    def bytes_java_to_py(val: jpype.JByte[:]):
        # Convert a JPype byte[] into a bytes object
        bytelist = list(
            map(lambda x: x.numerator if x.numerator >= 0 else 256 + x.numerator, val)
        )
        return bytes(bytelist)

    def __init__(self, platform: platforms.Platform):
        super().__init__(platform)
        self.platform: platforms.Platform = platform
        self.platdef: platforms.PlatformDef = platforms.PlatformDef.for_platform(
            platform
        )
        self.machdef: GhidraMachineDef = GhidraMachineDef.for_platform(platform)

        self._emu: PcodeEmulator = PcodeEmulator(self.machdef.language)
        # Set up the context configuration.
        # This includes execution mode information,
        # and isn't automatically propagated to the thread.
        self._thread.overrideContextWithDefault()

        self._memory_map = utils.RangeCollection()

        # Instruction hooking callbacks
        self._instructions_hook: typing.Optional[typing.Callable[[Emulator], None]] = (
            None
        )
        self._instruction_hooks: typing.Dict[int, typing.Callable[[Emulator], None]] = (
            dict()
        )

        # Function hooking callbacks
        self._function_hooks: typing.Dict[int, typing.Callable[[Emulator], None]] = (
            dict()
        )

        # Memory hooking callbacks
        self._mem_reads_hook: typing.Optional[
            typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]]
        ] = None
        self._mem_read_hooks: typing.Dict[
            typing.Tuple[int, int],
            typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
        ] = dict()
        self._mem_writes_hook: typing.Optional[
            typing.Callable[[Emulator, int, int, bytes], None]
        ] = None
        self._mem_write_hooks: typing.Dict[
            typing.Tuple[int, int], typing.Callable[[Emulator, int, int, bytes], None]
        ] = dict()

    @property
    def _thread(self) -> PcodeThread:
        return self._emu.getThread("main", True)

    def read_register_content(self, name: str) -> int:
        # Determine address and size of register
        if name == "pc":
            name = self.platdef.pc_register
        reg = self.machdef.pcode_reg(name)

        # Get the thread's register state
        state = self._thread.getState()

        # Get the register value in bytes
        val = state.getVar(reg, PcodeExecutorStatePiece.Reason.INSPECT)

        if self.platform.byteorder is platforms.Byteorder.LITTLE:
            return int.from_bytes(val, "little")
        elif self.platform.byteorder is platforms.Byteorder.BIG:
            return int.from_bytes(val, "big")
        else:
            raise Exception("Unable to decode byteorder {self.platform.byteorder}")

    def write_register_content(
        self, name: str, value: typing.Union[None, int, claripy.ast.bv.BV]
    ) -> None:
        # Determine address and size of register
        if name == "pc":
            name = self.platdef.pc_register
        reg = self.machdef.pcode_reg(name)

        if value is None:
            return
        if not isinstance(value, int):
            raise TypeError("Pcode emulator can't support symbolic values")

        state = self._thread.getState()

        if self.platform.byteorder is platforms.Byteorder.BIG:
            val = value.to_bytes(reg.getMinimumByteSize(), "big")
        elif self.platform.byteorder is platforms.Byteorder.LITTLE:
            val = value.to_bytes(reg.getMinimumByteSize(), "little")
        else:
            raise Exception("Unable to encode byteorder {self.platform.byteorder}")

        state.setVar(reg, self.bytes_py_to_java(val))

    def read_memory_content(self, address: int, size: int) -> bytes:
        # Get the thread's memory state
        shared = self._emu.getSharedState()

        if self.platform.byteorder is platforms.Byteorder.BIG:
            addr_bytes = address.to_bytes(self.platdef.address_size, "big")
        elif self.platform.byteorder is platforms.Byteorder.LITTLE:
            addr_bytes = address.to_bytes(self.platdef.address_size, "little")
        else:
            raise Exception("Unable to encode byteorder {self.platform.byteorder}")

        # Get the data out of the default address space
        # NOTE: Ghidra can support machines with multiple address spaces.
        # SmallWorld does not.
        val = shared.getVar(
            self.machdef.language.getDefaultSpace(),
            self.bytes_py_to_java(addr_bytes),
            size,
            False,
            shared.Reason.INSPECT,
        )
        return self.bytes_java_to_py(val)

    def map_memory(self, address: int, size: int) -> None:
        region = (address, address + size)
        self._memory_map.add_range(region)

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        return list(self._memory_map.ranges)

    def write_memory_content(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ):
        if isinstance(content, claripy.ast.bv.BV):
            raise TypeError("Pcode emulator can't handle symbolic expressions")

        log.info(f"Writing {hex(len(content))} bytes at {hex(address)}")

        # Get the thread's memory state
        shared = self._emu.getSharedState()

        val = self.bytes_py_to_java(content)
        if self.platform.byteorder is platforms.Byteorder.BIG:
            addr_bytes = address.to_bytes(self.platdef.address_size, "big")
        elif self.platform.byteorder is platforms.Byteorder.LITTLE:
            addr_bytes = address.to_bytes(self.platdef.address_size, "little")
        else:
            raise Exception("Unable to encode byteorder {self.platform.byteorder}")

        # Get the data out of the default address space
        # NOTE: Ghidra can support machines with multiple address spaces.
        # SmallWorld does not.
        shared.setVar(
            self.machdef.language.getDefaultSpace(),
            self.bytes_py_to_java(addr_bytes),
            len(content),
            False,
            val,
        )

    def hook_instruction(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        self._instruction_hooks[address] = function

    def unhook_instruction(self, address: int) -> None:
        if address in self._instruction_hooks:
            del self._instruction_hooks[address]

    def hook_instructions(self, function: typing.Callable[[Emulator], None]) -> None:
        self._instructions_hook = function

    def unhook_instructions(self) -> None:
        self._instructions_hook = None

    def _process_function_hook(self, address: int):
        if address not in self._function_hooks:
            # This really should never happen unless someone calls this manually.
            raise exceptions.ConfigurationError(f"No function hook at {hex(address)}")

        # Run the hook
        self._function_hooks[address](self)

        # Mimic a platform-specific "return" instruction.
        if self.platform.architecture == platforms.Architecture.X86_32:
            sp = self.read_register("esp")
            if self.platform.byteorder == platforms.Byteorder.LITTLE:
                ret = int.from_bytes(self.read_memory(sp, 4), "little")
            elif self.platform.byteorder == platforms.Byteorder.BIG:
                ret = int.from_bytes(self.read_memory(sp, 4), "big")
            self.write_register("esp", sp + 4)
        elif self.platform.architecture == platforms.Architecture.X86_64:
            # amd64: pop an 8-byte value off the stack
            sp = self.read_register("rsp")
            if self.platform.byteorder == platforms.Byteorder.LITTLE:
                ret = int.from_bytes(self.read_memory(sp, 8), "little")
            elif self.platform.byteorder == platforms.Byteorder.BIG:
                ret = int.from_bytes(self.read_memory(sp, 8), "big")
            self.write_register("rsp", sp + 8)
        elif (
            self.platform.architecture == platforms.Architecture.AARCH64
            or self.platform.architecture == platforms.Architecture.ARM_V5T
            or self.platform.architecture == platforms.Architecture.ARM_V6M
            or self.platform.architecture == platforms.Architecture.ARM_V6M_THUMB
            or self.platform.architecture == platforms.Architecture.ARM_V7A
            or self.platform.architecture == platforms.Architecture.ARM_V7M
            or self.platform.architecture == platforms.Architecture.ARM_V7R
            or self.platform.architecture == platforms.Architecture.POWERPC32
            or self.platform.architecture == platforms.Architecture.POWERPC64
        ):
            # aarch64, arm32, powerpc and powerpc64: branch to register 'lr'
            ret = self.read_register("lr")
        elif (
            self.platform.architecture == platforms.Architecture.LOONGARCH64
            or self.platform.architecture == platforms.Architecture.MIPS32
            or self.platform.architecture == platforms.Architecture.MIPS64
            or self.platform.architecture == platforms.Architecture.RISCV64
        ):
            # mips32, mips64, and riscv64: branch to register 'ra'
            ret = self.read_register("ra")
        elif self.platform.architecture == platforms.Architecture.XTENSA:
            # xtensa: branch to register 'a0'
            ret = self.read_register("a0")

        self.write_register("pc", ret)

    def hook_function(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        self._function_hooks[address] = function

    def unhook_function(self, address: int) -> None:
        if address in self._function_hooks:
            del self._function_hooks[address]

    def _update_access_breakpoints(self) -> None:
        # Refresh all access breakpoints
        # There's no way to clear a single access breakpoint;
        # you need to clear them all and re-apply.
        return

        # Wipe out all access breakpoints
        self._emu.clearAccessBreakpoints()

        addrspace = self.machdef.language.getDefaultSpace()

        # Add back the global read breakpoint
        if self._mem_reads_hook is not None:
            addr_range = AddressRangeImpl(
                addrspace.getMinAddress(), addrspace.getMaxAddress()
            )
            self._emu.addAccessBreakpoint(addr_range, self._emu.AccessKind.R)

        # Add back the specific read breakpoints
        for start, end in self._mem_read_hooks:
            start_addr = addrspace.getAddress(start)
            end_addr = addrspace.getAddress(end)
            addr_range = AddressRangeImpl(start_addr, end_addr)
            self._emu.addAccessBreakpoint(addr_range, self._emu.AccessKind.R)

        # Add back the global write breakpoint
        if self._mem_writes_hook is not None:
            addr_range = AddressRangeImpl(
                addrspace.getMinAddress(), addrspace.getMaxAddress()
            )
            self._emu.addAccessBreakpoint(addr_range, self._emu.AccessKind.W)

        # Add back the specific write breakpoints
        for start, end in self._mem_write_hooks:
            start_addr = addrspace.getAddress(start)
            end_addr = addrspace.getAddress(end)
            addr_range = AddressRangeImpl(start_addr, end_addr)
            self._emu.addAccessBreakpoint(addr_range, self._emu.AccessKind.W)

    def _process_read_breakpoint(
        self, addr_var: Varnode, out_var: Varnode, direct=False
    ) -> None:
        state = self._thread.getState()

        # Get the address out of the emulator
        if direct:
            # This is referencing a fixed address
            addr = addr_var.getAddress().getOffset()
        else:
            # This is referencing an address stored in a varnode
            addr_bytes = state.getVar(addr_var, PcodeExecutorStatePiece.Reason.INSPECT)
            if self.platform.byteorder is platforms.Byteorder.BIG:
                addr = int.from_bytes(addr_bytes, "big")
            elif self.platform.byteorder is platforms.Byteorder.LITTLE:
                addr = int.from_bytes(addr_bytes, "little")

        if not self._memory_map.contains_value(addr):
            raise exceptions.EmulationReadUnmappedFailure(
                "Read of unmapped data", self.read_register("pc"), address=addr
            )

        # Dereference the address to get the original data
        addr_space = self.machdef.language.getDefaultSpace()
        addr_addr = addr_space.getAddress(addr)
        data_var = Varnode(addr_addr, out_var.getSize())
        data = state.getVar(data_var, PcodeExecutorStatePiece.Reason.INSPECT)

        if self._mem_reads_hook is not None:
            new_data = self._mem_reads_hook(self, addr, len(data), data)
            if new_data is not None:
                data = new_data

        end_addr = addr + len(data)

        for (start, end), hook in self._mem_read_hooks.items():
            rng = range(start, end)
            access_rng = range(addr, end_addr)
            if (
                addr in rng
                or end_addr - 1 in rng
                or start in access_rng
                or end - 1 in access_rng
            ):
                new_data = hook(self, addr, len(data), data)
                if new_data is not None:
                    data = new_data

        # Write the data to the output
        #
        # CRITICAL: This must always happen, even if the op wasn't hooked!
        # The main processing loop skips any LOAD opcodes,
        # since their normal execution will clobber any value produced
        # by this handler.
        # Thus, this handler must fully replace the behavior of LOAD.
        state.setVar(out_var, self.bytes_py_to_java(data))

    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
    ) -> None:
        self._mem_read_hooks[(start, end)] = function
        self._update_access_breakpoints()

    def unhook_memory_read(self, start: int, end: int) -> None:
        if (start, end) in self._mem_read_hooks:
            del self._mem_read_hooks[(start, end)]
            self._update_access_breakpoints()

    def hook_memory_reads(
        self,
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
    ) -> None:
        self._mem_reads_hook = function
        self._update_access_breakpoints()

    def unhook_memory_reads(self) -> None:
        if self._mem_reads_hook is not None:
            self._mem_reads_hook = None
            self._update_access_breakpoints()

    def _process_write_breakpoint(
        self, addr_var: Varnode, data_var: Varnode, direct=False
    ) -> None:
        state = self._thread.getState()
        data = state.getVar(data_var, PcodeExecutorStatePiece.Reason.INSPECT)

        if direct:
            # This is referencing a fixed address.
            addr = addr_var.getAddress().getOffset()
        else:
            # This is referencing an address stored in a varnode.
            addr_bytes = state.getVar(addr_var, PcodeExecutorStatePiece.Reason.INSPECT)
            if self.platform.byteorder is platforms.Byteorder.BIG:
                addr = int.from_bytes(addr_bytes, "big")
            elif self.platform.byteorder is platforms.Byteorder.LITTLE:
                addr = int.from_bytes(addr_bytes, "little")

        if not self._memory_map.contains_value(addr):
            raise exceptions.EmulationWriteUnmappedFailure(
                "Write of unmapped data", self.read_register("pc"), address=addr
            )

        if self._mem_writes_hook is not None:
            self._mem_writes_hook(self, addr, len(data), data)

        end_addr = addr + len(data)

        for (start, end), hook in self._mem_write_hooks.items():
            rng = range(start, end)
            access_rng = range(addr, end_addr)
            if (
                addr in rng
                or end_addr - 1 in rng
                or start in access_rng
                or end - 1 in access_rng
            ):
                hook(self, addr, len(data), data)

    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes], None],
    ) -> None:
        self._mem_write_hooks[(start, end)] = function
        self._update_access_breakpoints()

    def unhook_memory_write(self, start: int, end: int) -> None:
        if (start, end) in self._mem_write_hooks:
            del self._mem_write_hooks[(start, end)]
            self._update_access_breakpoints()

    def hook_memory_writes(
        self,
        function: typing.Callable[[Emulator, int, int, bytes], None],
    ) -> None:
        self._mem_writes_hook = function
        self._update_access_breakpoints()

    def unhook_memory_writes(self) -> None:
        if self._mem_writes_hook is not None:
            self._mem_writes_hook = None
            self._update_access_breakpoints()

    def step_instruction(self) -> None:
        if not self.machdef.supports_single_step:
            raise exceptions.ConfigurationError(
                f"PcodeEmulator does not support single-instruction stepping for {self.platform}"
            )

        # Step!
        pc = self.read_register_content(self.platdef.pc_register)
        log.info(f"Stepping through {hex(pc)}")
        if not self._memory_map.contains_value(pc):
            raise exceptions.EmulationFetchUnmappedFailure(
                "Fetched unmapped memory", pc, address=pc
            )

        pc_addr = self.machdef.language.getDefaultSpace().getAddress(pc)
        self._thread.overrideCounter(pc_addr)

        # Check for instruction hooks.
        # TODO: Should instruction hooks override the instruction?
        if self._instructions_hook is not None:
            self._instructions_hook(self)
        if pc in self._instruction_hooks:
            self._instruction_hooks[pc](self)

        # Check for function hooks
        if pc in self._function_hooks:
            # Function hooks bypass normal instruction processing,
            # but I still want bounds/exits to work normally.
            self._process_function_hook(pc)
        else:
            skip = False
            frame = None
            # We need to step individual pcode ops to capture hooks
            # There is an exception-based hooking mechanism,
            # but it's unworkable for SmallWorld's purpose.
            while True:
                if skip:
                    # Skip the next op; it was modeled by a hook
                    skip = False
                    self._thread.skipPcodeOp()
                else:
                    # Execute the opcode normally
                    self._thread.stepPcodeOp()

                frame = self._thread.getFrame()

                if frame is None:
                    # No frame; this is the end of the instruction
                    break

                if frame.isFinished():
                    # Frame is finished; this is the end of the instruction
                    self._thread.finishInstruction()
                    break

                # Inspect the op to see if it's memory-hook relevant
                code = frame.getCode()
                op = code[frame.index()]
                opcode = op.getOpcode()
                if opcode == op.STORE:
                    # This is a STORE opcode; could trigger a "write" hook
                    _, addr_var, data_var = op.getInputs()
                    self._process_write_breakpoint(addr_var, data_var)
                elif opcode == op.LOAD:
                    # This is a LOAD opcode; could trigger a "read" hook
                    addr_space = self.machdef.language.getDefaultSpace()
                    default_id = addr_space.getSpaceID()

                    space_var, addr_var = op.getInputs()
                    out_var = op.getOutput()

                    space_id = space_var.getAddress().getOffset()

                    # Only trigger breakpoints on the primary address space.
                    # Ghidra uses a scratch address space for some operations.
                    # You very rarely see loads/stores to it, but they happen.
                    if space_id == default_id:
                        self._process_read_breakpoint(addr_var, out_var)
                        # Skip the actual LOAD opcode
                        # The read breakpoint handler will mimic its behavior;
                        # running the op normally will clobber a custom value
                        # produced by a hook.
                        skip = True
                elif opcode == op.COPY:
                    # This is a COPY opcode.
                    # It's used if copying directly between two varnodes,
                    # without having to compute an address.
                    # It could be a
                    addr_space = self.machdef.language.getDefaultSpace()

                    in_var = op.getInputs()[0]
                    out_var = op.getOutput()

                    in_space = in_var.getAddress().getAddressSpace()
                    out_space = out_var.getAddress().getAddressSpace()

                    if in_space == addr_space and out_space == addr_space:
                        # This is a read and write in a single opcode.
                        # Can't quite handle it; neither can most ISAs.
                        raise NotImplementedError(
                            f"RAM-to-RAM copy from {in_var} to {out_var}"
                        )
                    elif in_space == addr_space:
                        # This is a read from memory
                        self._process_read_breakpoint(in_var, out_var, direct=True)
                        skip = True
                    elif out_space == addr_space:
                        # This is a write to memory
                        self._process_write_breakpoint(out_var, in_var, direct=True)
                        skip = True

                    # This is not a memory access.  No need to break

        # Check exit points and bounds
        pc = self.read_register_content(self.platdef.pc_register)

        if pc in self._exit_points:
            raise exceptions.EmulationExitpoint()
        if not self._bounds.is_empty() and not self._bounds.contains_value(pc):
            raise exceptions.EmulationBounds()

    def step_block(self) -> None:
        raise NotImplementedError("Not sure how to step by block.")

    def run(self) -> None:
        try:
            while True:
                self.step_instruction()
        except exceptions.EmulationStop:
            pass

    def __repr__(self) -> str:
        return "PcodeEmulator"
