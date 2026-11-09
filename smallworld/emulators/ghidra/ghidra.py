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
from ..hookable import check_hookable_range, ranges_overlap
from .machdefs import GhidraMachineDef
from .machdefs.machdef import GhidraWrites
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
        # Whether the machine may redirect stores, and whether it derives
        # state from what instructions write; most do neither, and asking
        # costs every store a read of its address and data, and every op a
        # look at what it writes.
        self._redirects_stores = (
            type(self.machdef).redirect_store is not GhidraMachineDef.redirect_store
        )
        self._tracks_writes = (
            type(self.machdef).update_derived_state
            is not GhidraMachineDef.update_derived_state
        )

        self._emu: PcodeEmulator = PcodeEmulator(self.machdef.language)
        # The default address space is fixed for the emulator's lifetime;
        # cache it so per-pcode-op handlers don't re-cross the JPype boundary.
        self._default_space = self.machdef.language.getDefaultSpace()
        self._init_address_spaces()
        # Set up the context configuration.
        # This includes execution mode information,
        # and isn't automatically propagated to the thread.
        self._thread.overrideContextWithDefault()

        self._memory_map = utils.RangeCollection()

        # What has been written since the machine definition last updated
        # derived state; None until its first update.  Its own writes there
        # are not recorded.
        self._writes: typing.Optional[GhidraWrites] = None
        self._recording_writes = True

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

        self.machdef.initialize_state(self)

    def _init_address_spaces(self) -> None:
        # The address spaces SmallWorld's flat memory map covers, as
        # (space, flat base, size, width of an offset in bytes); a size of
        # None covers everything.  See GhidraMachineDef.address_spaces.
        self._spaces: typing.List[
            typing.Tuple[typing.Any, int, typing.Optional[int], int]
        ] = []
        if self.machdef.address_spaces is None:
            self._spaces.append(
                (self._default_space, 0, None, self.platdef.address_size)
            )
        else:
            factory = self.machdef.language.getAddressFactory()
            for name, base, size in self.machdef.address_spaces:
                space = factory.getAddressSpace(name)
                if space is None:
                    raise exceptions.ConfigurationError(
                        f"{self.machdef.language_id} has no address space {name}"
                    )
                self._spaces.append((space, base, size, space.getPointerSize()))
            if not any(
                space == self._default_space and base == 0
                for space, base, _, _ in self._spaces
            ):
                raise exceptions.ConfigurationError(
                    f"The default address space of {self.machdef.language_id} "
                    "must sit at flat address 0"
                )
        self._spaces_by_id = {
            space.getSpaceID(): (space, base) for space, base, _, _ in self._spaces
        }

    def _to_space(self, address: int, size: int) -> typing.Tuple[typing.Any, int, int]:
        """Translate a flat address to (space, offset, offset width)."""
        for space, base, span, width in self._spaces:
            if span is None:
                return space, address, width
            if base <= address < base + span:
                if address + size > base + span:
                    raise exceptions.ConfigurationError(
                        f"Access of {size} bytes at {hex(address)} runs off the "
                        f"end of address space {space.getName()}"
                    )
                return space, address - base, width
        raise exceptions.ConfigurationError(
            f"{hex(address)} is in no address space of {self.platform}"
        )

    def _offset_bytes(self, offset: int, width: int) -> typing.Any:
        return self.bytes_py_to_java(offset.to_bytes(width, self._byteorder_name()))

    def _mapped_space(
        self, space_id: int
    ) -> typing.Optional[typing.Tuple[typing.Any, int]]:
        """The (space, flat base) for a Ghidra space ID, if the flat map covers it."""
        return self._spaces_by_id.get(space_id)

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

        return int.from_bytes(val, self._byteorder_name())

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

        size = reg.getMinimumByteSize()
        # Mask to handle negative ints via two's-complement wraparound.
        value_unsigned = value & ((1 << (size * 8)) - 1)
        val = value_unsigned.to_bytes(size, self._byteorder_name())

        state.setVar(reg, self.bytes_py_to_java(val))
        self._note_register_write(reg.getAddress().getOffset(), size)

    def _note_register_write(self, offset: int, size: int) -> None:
        if self._recording_writes and self._writes is not None:
            self._writes.registers.add((offset, size))

    def _note_memory_write(self, address: int, size: int) -> None:
        if self._recording_writes and self._writes is not None:
            self._writes.memory.add((address, size))

    def _update_derived_state(self) -> None:
        self._recording_writes = False
        try:
            self.machdef.update_derived_state(self, self._writes)
        finally:
            self._recording_writes = True
        self._writes = GhidraWrites()

    def _update_pending_derived_state(self) -> None:
        # Bring derived state up to date if anything was written since it
        # last was.
        if self._tracks_writes and (self._writes is None or self._writes):
            self._update_derived_state()

    def read_memory_content(self, address: int, size: int) -> bytes:
        # Get the thread's memory state
        shared = self._emu.getSharedState()

        # Find the address space this flat address belongs to;
        # on most machines that's the default space.
        space, offset, width = self._to_space(address, size)
        val = shared.getVar(
            space,
            self._offset_bytes(offset, width),
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

        # Get the thread's memory state
        shared = self._emu.getSharedState()

        val = self.bytes_py_to_java(content)

        # Find the address space this flat address belongs to;
        # on most machines that's the default space.
        space, offset, width = self._to_space(address, len(content))
        shared.setVar(
            space,
            self._offset_bytes(offset, width),
            len(content),
            False,
            val,
        )
        self._note_memory_write(address, len(content))

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

    def hook_function(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        self._function_hooks[address] = function

    def unhook_function(self, address: int) -> None:
        if address in self._function_hooks:
            del self._function_hooks[address]

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

    def _require_mapped(
        self,
        addr: int,
        size: int,
        exc: typing.Type[exceptions.EmulationMemoryFailure],
        verb: str,
        hooks: typing.Iterable[typing.Tuple[int, int]] = (),
    ) -> None:
        # contains_value() only checks the starting byte; a multi-byte access
        # can begin inside a mapped region and run off its end into unmapped
        # memory. Validate every byte of [addr, addr + size) and report the
        # first unmapped one.
        #
        # An access directed at a hooked (MMIO) region is a special case: the
        # region's model owns the access semantics and may legitimately be
        # declared narrower than the instruction that reads/writes it (e.g. a
        # 1-byte device polled with a word-sized load). The model, not the
        # backing store, supplies the value, so skip the span check when the
        # access begins inside a hooked range. This keeps ordinary RAM strict
        # -- a read/write that starts in plain memory and runs off the end into
        # unmapped space is still rejected.
        for start, end in hooks:
            if start <= addr < end:
                return

        missing = self._memory_map.get_missing_ranges((addr, addr + size))
        if missing:
            raise exc(
                f"{verb} of unmapped data",
                self.read_register("pc"),
                address=missing[0][0],
            )

    def _process_read_breakpoint(
        self,
        addr_var: Varnode,
        out_var: Varnode,
        direct=False,
        space: typing.Optional[typing.Tuple[typing.Any, int]] = None,
    ) -> None:
        state = self._thread.getState()
        offset = self._access_offset(addr_var, direct)

        # Hooks and the memory map see flat addresses.
        addr_space, base = space if space is not None else (self._default_space, 0)
        addr = base + offset

        self._require_mapped(
            addr,
            out_var.getSize(),
            exceptions.EmulationReadUnmappedFailure,
            "Read",
            self._mem_read_hooks,
        )

        # Dereference the address to get the original data
        addr_addr = addr_space.getAddress(offset)
        data_var = Varnode(addr_addr, out_var.getSize())
        data = state.getVar(data_var, PcodeExecutorStatePiece.Reason.INSPECT)

        if self._mem_reads_hook is not None:
            new_data = self._mem_reads_hook(self, addr, len(data), data)
            if new_data is not None:
                data = new_data

        end_addr = addr + len(data)

        for (start, end), hook in self._mem_read_hooks.items():
            if ranges_overlap(range(addr, end_addr), range(start, end)):
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

    def _byteorder_name(self) -> typing.Literal["big", "little"]:
        return "big" if self.platform.byteorder is platforms.Byteorder.BIG else "little"

    def _access_offset(self, addr_var: Varnode, direct: bool) -> int:
        """The offset into its space that a load or store reaches."""
        if direct:
            # This is referencing a fixed address.
            return addr_var.getAddress().getOffset()
        # This is referencing an address stored in a varnode.
        return self._read_varnode(addr_var)

    def _read_varnode(self, var: Varnode) -> int:
        """Read a p-code varnode as an unsigned integer."""
        state = self._thread.getState()
        val = state.getVar(var, PcodeExecutorStatePiece.Reason.INSPECT)
        return int.from_bytes(val, self._byteorder_name())

    def _write_varnode(self, var: Varnode, value: int) -> None:
        """Write an integer to a p-code varnode, truncated to its size."""
        size = var.getSize()
        data = (value & ((1 << (size * 8)) - 1)).to_bytes(size, self._byteorder_name())
        self._thread.getState().setVar(var, self.bytes_py_to_java(data))

    def _process_userop(self, op) -> None:
        # Mirrors the angr backend's userop tables: look the op up in the
        # machine's GhidraUserOp enum and let its handler perform it.
        assert self.machdef.userops is not None
        opnum = int(op.getInputs()[0].getOffset())
        if opnum not in self.machdef.userops:
            raise exceptions.EmulationError(f"Undefined user op {hex(opnum)}")
        userop = self.machdef.userops(opnum)
        userop.handler(self, op)

    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
    ) -> None:
        check_hookable_range(start, end, "memory read")
        self._mem_read_hooks[(start, end)] = function

    def unhook_memory_read(self, start: int, end: int) -> None:
        if (start, end) in self._mem_read_hooks:
            del self._mem_read_hooks[(start, end)]

    def hook_memory_reads(
        self,
        function: typing.Callable[[Emulator, int, int, bytes], typing.Optional[bytes]],
    ) -> None:
        self._mem_reads_hook = function

    def unhook_memory_reads(self) -> None:
        if self._mem_reads_hook is not None:
            self._mem_reads_hook = None

    def _store_target(
        self,
        addr_var: Varnode,
        data_var: Varnode,
        direct=False,
        space: typing.Optional[typing.Tuple[typing.Any, int]] = None,
    ) -> typing.Tuple[int, typing.Any]:
        # The flat address a store writes, and what it writes, as Ghidra
        # holds it.
        state = self._thread.getState()
        data = state.getVar(data_var, PcodeExecutorStatePiece.Reason.INSPECT)
        offset = self._access_offset(addr_var, direct)

        # Hooks and the memory map see flat addresses.
        return (space[1] if space is not None else 0) + offset, data

    def _process_write_breakpoint(
        self,
        addr_var: Varnode,
        data_var: Varnode,
        direct=False,
        space: typing.Optional[typing.Tuple[typing.Any, int]] = None,
    ) -> None:
        self._write_hooks(*self._store_target(addr_var, data_var, direct, space))

    def _write_hooks(self, addr: int, data: typing.Any) -> None:
        # What _process_write_breakpoint does, given the store's flat address
        # and data.
        self._note_memory_write(addr, len(data))

        self._require_mapped(
            addr,
            len(data),
            exceptions.EmulationWriteUnmappedFailure,
            "Write",
            self._mem_write_hooks,
        )

        if self._mem_writes_hook is not None:
            self._mem_writes_hook(self, addr, len(data), data)

        end_addr = addr + len(data)

        for (start, end), hook in self._mem_write_hooks.items():
            if ranges_overlap(range(addr, end_addr), range(start, end)):
                hook(self, addr, len(data), data)

    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes], None],
    ) -> None:
        check_hookable_range(start, end, "memory write")
        self._mem_write_hooks[(start, end)] = function

    def unhook_memory_write(self, start: int, end: int) -> None:
        if (start, end) in self._mem_write_hooks:
            del self._mem_write_hooks[(start, end)]

    def hook_memory_writes(
        self,
        function: typing.Callable[[Emulator, int, int, bytes], None],
    ) -> None:
        self._mem_writes_hook = function

    def unhook_memory_writes(self) -> None:
        if self._mem_writes_hook is not None:
            self._mem_writes_hook = None

    def step_instruction(self) -> None:
        if not self.machdef.supports_single_step:
            raise exceptions.ConfigurationError(
                f"PcodeEmulator does not support single-instruction stepping for {self.platform}"
            )

        # Bring derived state up to date with anything written since the
        # last instruction, by the harness say; then the machine may
        # redirect execution between instructions, taking an interrupt,
        # which writes state of its own.
        self._update_pending_derived_state()
        self.machdef.before_instruction(self)
        self._update_pending_derived_state()

        # Step!
        pc = self.read_register_content(self.platdef.pc_register)
        log.debug(f"Stepping through {hex(pc)}")
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
        # The instruction must see what the hooks wrote.
        self._update_pending_derived_state()

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

                # Record what it writes, for the machine definition.
                out = op.getOutput() if self._tracks_writes else None
                if out is not None:
                    if out.isRegister():
                        self._note_register_write(out.getOffset(), out.getSize())
                    else:
                        out_space = self._mapped_space(
                            out.getAddress().getAddressSpace().getSpaceID()
                        )
                        if out_space is not None:
                            self._note_memory_write(
                                out_space[1] + out.getOffset(), out.getSize()
                            )
                if opcode == op.CALLOTHER and self.machdef.userops is not None:
                    # A user-defined operation; the machine definition's
                    # handler performs it in place of the op.
                    self._process_userop(op)
                    skip = True
                elif opcode == op.STORE:
                    # This is a STORE opcode; could trigger a "write" hook
                    space_var, addr_var, data_var = op.getInputs()
                    space = self._mapped_space(space_var.getAddress().getOffset())
                    if space is None and self.machdef.address_spaces is None:
                        # Single-space machines treat every store as
                        # a store to the default space.
                        space = (self._default_space, 0)
                    if space is not None:
                        address, data = self._store_target(
                            addr_var, data_var, space=space
                        )
                        # The machine may perform the store another way; see
                        # GhidraMachineDef.redirect_store.
                        if self._redirects_stores and self.machdef.redirect_store(
                            self, address, bytes(data)
                        ):
                            skip = True
                        else:
                            self._write_hooks(address, data)
                elif opcode == op.LOAD:
                    # This is a LOAD opcode; could trigger a "read" hook
                    space_var, addr_var = op.getInputs()
                    out_var = op.getOutput()

                    # Only trigger breakpoints on the spaces SmallWorld maps.
                    # Ghidra uses a scratch address space for some operations.
                    # You very rarely see loads/stores to it, but they happen.
                    space = self._mapped_space(space_var.getAddress().getOffset())
                    if space is not None:
                        self._process_read_breakpoint(addr_var, out_var, space=space)
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
                    in_var = op.getInputs()[0]
                    out_var = op.getOutput()

                    in_space = self._mapped_space(
                        in_var.getAddress().getAddressSpace().getSpaceID()
                    )
                    out_space = self._mapped_space(
                        out_var.getAddress().getAddressSpace().getSpaceID()
                    )

                    if in_space is not None and out_space is not None:
                        if self.machdef.address_spaces is None:
                            # This is a read and write in a single opcode.
                            # Can't quite handle it; neither can most ISAs.
                            raise NotImplementedError(
                                f"RAM-to-RAM copy from {in_var} to {out_var}"
                            )
                        # Harvard machines move between their spaces
                        # directly (8051 `mov direct, direct`).  The read
                        # handler performs the copy, writing the (possibly
                        # hooked) data into out_var, and then the write
                        # hooks see what landed there.
                        self._process_read_breakpoint(
                            in_var, out_var, direct=True, space=in_space
                        )
                        self._process_write_breakpoint(
                            out_var, out_var, direct=True, space=out_space
                        )
                        skip = True
                    elif in_space is not None:
                        # This is a read from memory
                        self._process_read_breakpoint(
                            in_var, out_var, direct=True, space=in_space
                        )
                        skip = True
                    elif out_space is not None:
                        # This is a write to memory.  Write hooks only
                        # observe, so let the op run and perform the write.
                        self._process_write_breakpoint(
                            out_var, in_var, direct=True, space=out_space
                        )

                    # This is not a memory access.  No need to break

        if self._tracks_writes:
            self._update_derived_state()

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
