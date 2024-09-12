from __future__ import annotations

import logging
import sys
import typing

import capstone
import unicorn
import unicorn.ppc_const  # Not properly exposed by the unicorn module

from ... import exceptions, instructions, state
from .. import emulator, hookable
from .machdefs import UnicornMachineDef
from enum import Enum


logger = logging.getLogger(__name__)


class UnicornEmulationError(EmulationError):
    def __init__(self, uc_err: unicorn.UcError, pc: int, msg:str, details: dict):
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


class UnicornEmulator(emulator.Emulator, hookable.QInstructionHookable, hookable.QFunctionHookable, \
                      hookable.QMemoryReadHookable, hookable.QMemoryWriteHookable, hookable.QInterruptHookable):
    """An emulator for the Unicorn emulation engine.

    Arguments:
        arch: Architecture ID string
        mode: Mode ID string
        byteorder: Byteorder

    """

    PAGE_SIZE = 0x1000

    # If in bounds for at least one of the allowed execuction intervals
    # provided, then we are "in-bounds", else raise exception
    def _check_pc_in_bounds(self, pc):            
        any_in_bounds = False
        for bound in self.bounds:
            if pc in bound:
                any_in_bounds = True
                break
        if any_in_bounds:
            return
        if self.emulation_in_progress == STEP_BLOCK or self.emulation_in_progress == RUN:
            self.engine.emu_stop()
        raise exceptions.EmulationBounds
    
    def __init__(self, arch: str, mode: str, byteorder: str):
        super().__init__()
        self.arch = arch
        self.mode = mode
        self.byteorder = byteorder
        self.machdef = UnicornMachineDef.for_arch(arch, mode, byteorder)
        self.engine = unicorn.Uc(self.machdef.uc_arch, self.machdef.uc_mode)
        self.disassembler = capstone.Cs(self.machdef.cs_arch, self.machdef.cs_mode)
        self.disassembler.detail = True

        self.bounds: typing.Iterable[range] = []

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
        self.label: typing.Dict[str, str]

        # mmio read and write hooking data structs
        self.mmio_read_hooks: typing.Dict[
            int,
            typing.List[
                typing.Tuple[
                    int, int, typing.Callable[[emulator.Emulator, int, int], bytes]
                ]
            ],
        ] = {}
        self.mmio_write_hooks: typing.Dict[
            int,
            typing.List[
                typing.Tuple[
                    int,
                    int,
                    typing.Callable[[emulator.Emulator, int, int, bytes], None],
                ]
            ],
        ] = {}
        
        # NB: instruction, function, memory read and write, and interrupt hook
        # data (what to hook and function to run) are provided by
        # `UnicornInstructionHookable` inheritance etc.
        # this is used to be able to "return" from a function without running it
        self.hook_return = None

        # list of exit points which will end emulation
        self.exit_points = []                

        # this will run on *every instruction
        def code_callback(uc, address, size):
            # check for if we've hit an exit point
            if address in self.exit_points:
                logger.debug(f"stopping emulation at exit point {address:x}")
                self.engine.emu_stop()
                raise exception.EmulationExitpoint
            # run instruciton hooks
            if address in self.instruction_hooks:
                logger.debug(f"hit hooking address for instruction at {address:x}")
                self.instruction_hooks[address]()
            # check function hooks *before* bounds since these might be out-of-bounds
            if address in self.function_hooks:
                logger.debug(f"hit hooking address for function at {address:x}")
                # note that hooking a function means that we stop at function
                # entry and, after running the hook, we do not let the function
                # execute. Instead, we return from the function as if it ran.
                # this permits modeling
                # this is the model for the function
                self.function_hooks[address]()
                self.engine.emu_stop()                
                if self.hook_return is None:
                    raise RuntimeError("return point for function hook is unknown")
                self.write_register("pc", self.hook_return)
            elif: 
                # check if we are out of bounds
                self._check_pc_in_bounds(self, address)
            # this is always keeping track of *next* instruction which, would be
            # return addr for a call.
            self.hook_return = address + size
                
        self.engine.hook_add(unicorn.UC_HOOK_CODE, code_callback)

        # functions to run before memory read and write for
        # specific addresses
        self.memory_read_hooks = {}
        self.memory_write_hooks = {}
        
        def mem_read_callback(uc, type, address, size, value, user_data):
            assert (type == unicorn.UC_HOOK_MEM_READ)
            if address in self.memory_read_hooks:
                self.memory_read_hooks[address](address, size)

        def mem_write_callback(uc, type, address, size, value, user_data):
            assert (type == unicorn.UC_HOOK_MEM_WRITE)
            if address in self.memory_write_hooks:
                self.memory_write_hooks[address][address, size)

        self.engine.hook_add(unicorn.UC_MEM_WRITE, mem_write_callback)
        self.engine.hook_add(unicorn.UC_MEM_READ, mem_read_callback)

        # function to run on *every* interrupt
        self.interrupts_hook = None
        
        # function to run on a specific interrupt number
        self.interrupt_hook = {}

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
                
        self.bounds = []

        # keep track of which registers have been initialized
        self.initialized_registers = {}


    def _register(self, name: str) -> int:
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
        (reg, _, _ , _) = self._register(name)
        if reg == 0:
            logger.warn(
                f"Unicorn doesn't support register {name} for {self.arch}:{self.mode}:{self.byteorder}"
            )
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
            ls = set([])
            for i in range(offset, offset+size):                
                if i in self.label[base_reg]:
                    ls.add(self.label[base_reg][i])
            return ":".join(list(ls))
        return None

    
    def read_register(self, name: str) -> int:
        return self.read_register_content(name)    

    
    def write_register_content(self, name: str, content: int) -> None:
        if value is None:
            logger.debug(f"ignoring register write to {name} - no value")
            return
        (reg, base_reg, offset, size) = self._register(name)
        self.engine.reg_write(reg, value)        
        # keep track of which bytes in this register have been initialized 
        if base_reg not in self.initialized_registers:
            self.initialized_registers[base_reg] = {}
        for o in range(offset, offset+size):
            self.initialized_registers[base_reg].add(o)
        logger.debug(f"set register {name}={value}")

        
    def write_register_type(
        self, name: str, typ: typing.Optional[typing.Any] = None
    ) -> None:
        # not supported yet
        pass

    
    def write_register_label(
        self, name: str, label: typing.Optional[str] = None
    ) -> None:
        (_, base_reg, offset, size) = self._register(name)
        if base_reg not in self.label:
            self.label[base_reg] = {}
        for i in range(offset, offset+size):
            self.label[base_reg][i] = label            

            
    def write_register(self, name: str, content: int) -> None:
        self.write_register_content(name, content)

        
    def read_memory_content(self, address: int, size: int) -> bytes:
        if size > sys.maxsize:
            raise ValueError(f"{size} is too large (max: {sys.maxsize})")
        try:
            return self.engine.mem_read(address, size)
        except unicorn.UcError as e:
            logger.warn(f"Unicorn raised an exception on memory read {new_e.msg}")
            self._error(e, "mem")

            
    def read_memory_type(self, address: int, size: int) -> typing.Optional[typing.Any]:
        # not supported yet
        return None

    
    def read_memory_label(self, address: int, size: int) -> typing.Optional[str]:
        ls = set([])
        for a in range(address, address+size):
            addr_key = f"{a:x}"
            if addr_key in self.label:
                ls.add(self.label[addr_key])
        if len(ls) == 0:
            return None
        return ":".join(list(ls))

    
    def read_memory(self, address: int, size: int) -> bytes:
        return self.read_memory_content(address, size)

    
    def map_memory(self, size: int, address: typing.Optional[int] = None) -> int:
        
        def page(address: int) -> int:
            """Compute the page number of an address.

            Returns:
                The page number of this address.
            """

            return address // self.PAGE_SIZE

        def subtract(first, second):
            result = []
            endpoints = sorted((*first, *second))
            if endpoints[0] == first[0] and endpoints[1] != first[0]:
                result.append((endpoints[0], endpoints[1]))
            if endpoints[3] == first[1] and endpoints[2] != first[1]:
                result.append((endpoints[2], endpoints[3]))

            return result

        def map(start: int, end: int):
            """Map a region of memory by start and end page.

            Arguments:
                start: Starting page of allocation.
                end: Ending page of allocation.
            """

            address = start * self.PAGE_SIZE
            allocation = (end - start) * self.PAGE_SIZE

            logger.debug(f"new memory map 0x{address:x}[{allocation}]")

            self.engine.mem_map(address, allocation)

        # Fixed address, map only pages which are not yet mapped.
        if address:
            region = (page(address), page(address + size) + 1)

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

        # Address not provided, find a suitable region.
        else:
            target = 0
            for start, end, _ in self.engine.mem_regions():
                if page(end) > target:
                    target = page(end) + 1

            map(target, target + page(size) + 1)
            address = target * self.PAGE_SIZE

        return address

    
    def write_memory_content(self, address: int, content: bytes) -> None:
        if content is None:
            raise ValueError(f"{self.__class__.__name__} requires concrete state")

        if len(content) > sys.maxsize:
            raise ValueError(f"{len(content)} is too large (max: {sys.maxsize})")

        if not len(content):
            raise ValueError("memory write cannot be empty")

        try:
            self.engine.mem_write(address, content)
        except unicorn.UcError as e:
            logger.warn(f"Unicorn raised an exception on memory write {new_e.msg}")
            self._error(e, "mem")

        logger.debug(f"wrote {len(content)} bytes to 0x{address:x}")

        
    def write_memory_type(
        self, address: int, size:int, type: typing.Optional[typing.Any] = None
    ) -> None:
        # not supported yet
        pass

    
    def write_memory_label(
        self, address: int, size:int, label: typing.Optional[str] = None
    ) -> None:
        for a in range(address, address+size):
            self.label[f"{a:x}"] = label            

            
    def write_memory(self, address: int, content: bytes) -> None:
        self.write_memory_content(address, content)

        
    def hook_mmio(
        self,
        address: int,
        size: int,
        on_read: typing.Optional[
            typing.Callable[[emulator.Emulator, int, int], bytes]
        ] = None,
        on_write: typing.Optional[
            typing.Callable[[emulator.Emulator, int, int, bytes], None]
        ] = None,
    ):
        # Unicorn is not quite as flexible as angr;
        # it requires mapping an entire page for an MMIO region.
        mmio_lo = address - (address % 0x1000)
        mmio_hi = address + size + 0xFFF
        mmio_hi = mmio_hi - (mmio_hi % 0x1000)

        if on_read is None and on_write is None:
            raise exceptions.AnalysisError(
                "Must specify at least one callback to hook_memory"
            )

        for a in range(mmio_lo, mmio_hi, 0x1000):
            # Unicorn hooks mmio one 4k page at a time.
            # To hook finer than that, we need to hook the entire page,
            # and then search a list of hooks for one that matches.
            # For ease of handling, mmio is registered in 4k blocks;
            # no need to merge or split.
            for a in range(mmio_lo, mmio_hi, 0x1000):
                if a not in self.mmio_read_hooks:

                    def read_callback(uc, read_off, read_sz, ud):
                        read_addr = a + read_off
                        for addr, sz, hook in self.mmio_read_hooks[a]:
                            if addr <= read_addr and addr + sz >= read_addr + read_sz:
                                res = hook(self, read_addr, read_sz)
                                logger.info(f"Got {res} for {read_addr:x},{read_sz}")
                                return int.from_bytes(res, self.machdef.byteorder)
                        raise exceptions.AnalysisError(
                            "Caught unhandled MMIO read of size {sz} at {read_addr:x}"
                        )

                    def write_callback(uc, write_off, write_sz, write_val, ud):
                        write_addr = a + write_off
                        for addr, sz, hook in self.mmio_write_hooks[a]:
                            if (
                                addr <= write_addr
                                and addr + sz >= write_addr + write_sz
                            ):
                                val = write_val.to_bytes(size, self.machdef.byteorder)
                                hook(self, write_addr, write_sz, val)
                                return
                        raise exceptions.AnalysisError(
                            "Caught unhandled MMIO read of size {sz} at {read_addr:x}"
                        )

                    self.engine.mmio_map(
                        a, 0x1000, read_callback, None, write_callback, None
                    )

                read_hooks = self.mmio_read_hooks.setdefault(a, list())
                write_hooks = self.mmio_write_hooks.setdefault(a, list())

                if on_read is not None:
                    read_hooks.append((address, size, on_read))
                if on_write is not None:
                    write_hooks.append((address, size, on_write))

                    
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
        (_, base_name, offset, size)  = self._register("pc")
        if base_name in self.initialized_registers and \
           len(self.initialized_registers[base_name]) == size:
               # pc is fully initialized
               pass
        else:
            raise exceptions.ConfigurationError(
                "pc not initialized, emulation cannot start"
            )
        # 2. an exit point is also required
        if len(self.exit_points) == 0:
            raise exceptions.ConfigurationError(
                "at least one exit point must be set, emulation cannot start"
            )

        
    def _step(self, by_block:bool=False) -> None:
        self._check()

        # by_block == True means stepping by a basic block at a time
        # by_block == False means stepping by instruction
        self.stepping_by_block = by_block        

        pc = self.read_register("pc")

        if by_block:
            # hard to disassemble bb about to be emulated?
            logger.info(f"block step at 0x{pc:x}")
        else:
            code = self.read_memory(pc, 15)  # longest possible instruction
            if code is None:            
                assert False, "impossible state"
            (instr, disas) = self.disassemble(code, pc, 1)
            logger.info(f"single step at 0x{pc:x}: {disas}")
            
        try: 
            # NB: unicorn requires an exit point so just use first in our
            # list. Note that we still check all of them at each instruction in
            # code callback
            if by_block:
                # stepping by block -- just start emulating and the block
                # callback will end emulation when we hit next bb
                # Note: assuming no block will be longer than 1000 instructions
                self.engine.emu_start(pc, self.exit_point[0], count=1000)
            else:
                # stepping by instruction
                self.engine.emu_start(pc, self.exit_point[0], count=1)
        except unicorn.UcError as e:            
            logger.warn(f"emulation stopped - reason: {e}")
            # translate this unicorn error into something richer
            self._error(e, "exec")

            
    def step_instruction(self) -> bool:
        self._step()

    
    def step_block(self) -> bool:
        
        self._step(by_block=True)

    
    def run(self) -> None:
        self._check()
                
        logger.info(f"starting emulation at 0x{self.read_register('pc'):x} until 0x{self.exit:x}")

        try:
            # unicorn requires one exit point so just use first
            self.engine.emu_start(self.read_register('pc'), self.exit_points[0])
        except unicorn.UcError as e:
            logger.warn(f"emulation stopped - reason: {e}")
            logger.warn("for more details, run emulation in single step mode")
            self._error(e, "exec")

        logger.info("emulation complete")

        
    def _error(
        self, error: unicorn.UcError, typ:str
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
            raise AssertionError("invalid state -- cannot obtain code from memory for current pc")

        insns, _ = self.disassemble(code, 1)
        i = instructions.Instruction.from_capstone(insns[0])

        if typ == "mem":
            if error.errno == unicorn.UC_ERR_READ_UNMAPPED:
                msg = "Quit emulation due to read of unmapped memory"
                details = {o.key(self): o.concretize(self) for o in i.reads}
            elif error.errno == unicorn.UC_ERR_WRITE_UNMAPPED:
                msg = "Quit emulation due to write to unmapped memory"
                details = {o.key(self): o.concretize(self) for o in i.writes}
            elif error.errno == unicorn.UC_ERR_FETCH_UNMAPPED:
                msg = "Quit emulation due to fetch of unmapped memory"
                details = {"pc": pc}
            elif error.errno == unicorn.UC_ERR_READ_PROT:
                msg = "Quit emulation due to read of mapped but protected memory"
                details = {o.key(self): o.concretize(self) for o in i.reads}
            elif error.errno == unicorn.UC_ERR_WRITE_PROT:
                msg = "Quit emulation due to write to mapped but protected memory"
                details = {o.key(self): o.concretize(self) for o in i.writes}
            elif error.errno == unicorn.UC_ERR_FETCH_PROT:
                msg = "Quit emulation due to fetch of from mapped but protected memory"
                details = {"pc": pc}
            elif error.errno == unicorn.UC_ERR_READ_UNALIGNED:
                msg = "Quit emulation due to unaligned read"
                details = {o.key(self): o.concretize(self) for o in i.reads}
            elif error.errno == unicorn.UC_ERR_WRITE_UNALIGNED:
                msg = "Quit emulation due to unaligned write"
                details = {o.key(self): o.concretize(self) for o in i.writes}
            elif error.errno == unicorn.UC_ERR_FETCH_UNALIGNED:
                msg = "Quit emulation due to unaligned fetch"
                details = {"pc": pc}
            else:
                raise ValueError(f"errno={error.errno} not valid for typ='mem'")
            raise UnicornEmulationMemoryError(error, pc, msg, details)
        elif typ == "exec":
            if error.errno == unicorn.UC_ERR_NONMEM:
                msg = "Quit emulation due Out-Of-Memory"
                details = {"pc": pc}
            elif error.errno == unicorn.UC_ERR_INSN_INVALID:
                msg = "Quit emulation due invalid instruction"
                details = {"pc": pc, pc: code}
            elif error.errno == unicorn.UC_ERR_RESOURCE:
                msg = "Quit emulation due insufficient resources"
                details = {"pc": pc}
            elif error.errno == unicorn.UC_ERR_EXCEPTION:
                msg = "Quit emulation due cpu exception"
                details = {"pc": pc}
            else:
                raise ValueError(f"errno={error.errno} not valid for typ='exec'")
            raise UnicornEmulationExecutionError(error, pc, msg, details)
        
        raise ValueError(f"typ={typ} is not known")
            

    def __repr__(self) -> str:
        return f"Unicorn(mode={self.mode}, arch={self.arch})"
