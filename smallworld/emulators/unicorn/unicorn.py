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




class UnicornInstructionHookable(InstructionHookable):
    pass

        
class UnicornFunctionHookable(FunctionHookable):
    pass


class UnicornMemoryReadHookable(MemoryReadHookable):
    pass


class UnicornMemoryWriteHookable(MemoryWriteHookable):
    pass


class UnicornEmulator(emulator.Emulator, UnicornInstructionHookable, UnicornFunctionHookable, UnicornMemoryReadHookable, UnicornMemoryWriteHookable, UnicornInterruptHookable):
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

        self.engine = unicorn.Uc(self.machdef.uc_arch, self.machdef.uc_mode)

        self.disassembler = capstone.Cs(self.machdef.cs_arch, self.machdef.cs_mode)
        self.disassembler.detail = True

        # keep track of which registers have been initialized
        self.initialized_registers = {}

        self.bounds: typing.Iterable[range] = []
        # one label per byte.
        # So we'll have one entry per full-width base register
        # and those themselves are map from offset within the register to string label
        # for 64-bit x86, we'd have
        # self.label["rax"][0] = "input" e.g.
        # but no self.label["eax"] -- you have to look in "rax"
        # For memory, we have one label per byte in memory
        # self.label["0xdeadbeef"] = "came_from_hades"
        self.label: typing.Dict[str, str]

        # Note: here are the hooks Unicorn seems to offer
        # UC_HOOK_INTR = 1 << 0,              -- interrupts
        # UC_HOOK_INSN = 1 << 1,              -- *certain* instructions: cpuid, syscalls, 
        # UC_HOOK_CODE = 1 << 2,              -- individual instructions?
        # UC_HOOK_BLOCK = 1 << 3,             -- before block exec?
        # UC_HOOK_MEM_READ_UNMAPPED = 1 << 4,   
        # UC_HOOK_MEM_WRITE_UNMAPPED = 1 << 5,
        # UC_HOOK_MEM_FETCH_UNMAPPED = 1 << 6,
        # UC_HOOK_MEM_READ_PROT = 1 << 7,
        # UC_HOOK_MEM_WRITE_PROT = 1 << 8,
        # UC_HOOK_MEM_FETCH_PROT = 1 << 9,
        # UC_HOOK_MEM_READ = 1 << 10,        -- before every load
        # UC_HOOK_MEM_WRITE = 1 << 11,       -- before very store
        # UC_HOOK_MEM_FETCH = 1 << 12,
        # UC_HOOK_MEM_READ_AFTER = 1 << 13,   
        # UC_HOOK_INSN_INVALID = 1 << 14,     -- invalid instructions
        
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

        # code_hooks: function to run before instructions at particular pcs or
        # functions that start at particular pcs 
        self.code_hooks: typing.Dict[
            int, typing.Tuple[typing.Callable[[emulator.Emulator, int, int], None], bool]
        ] = {}
        # this is used to be able to "return" from a function without running it
        self.hook_return = None

        # list of exit points
        self.exit_points = []
                
        def code_callback(uc, address, size):

            # check for if we've hit an exit point
            if address in self.exit_points:
                self.engine.emu_stop()

            if address in self.code_hooks:
                logger.debug(f"hit hooking address for instruction/function at {address:x}")
                hook, finish = self.code_hooks[address]

                hook(self)

                if finish:
                    if self.hook_return is None:
                        raise RuntimeError("return point unknown")
                    self.write_register("pc", self.hook_return)
                    self.hook_return = None

            self.hook_return = address + size

        self.engine.hook_add(unicorn.UC_HOOK_CODE, code_callback)

        self block_hooks: typing.Dict[
            int, typing.Callable[[emulator.Emulator, int, int], None]
        ] = {}

        def block_callback(uc, address, size):
                                    
            if address in self.block_hooks:
                logger.debug(f"hit hooking address for block starting {address:x}")
                hook = self.block_hooks[address]
                hook(self)                
        
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

        # func to run on *every* interrupt
        self.interrupts_hook = None
        
        # func to run on a specific interrupt number
        self.interrupt_hook = {}

        def intr_callback(uc, index, user_data):
            if self.interrupts_hook is not None:
                self.interrupts_hook()
            if index in self.interrupt_hook:
                self.interrupt_hook[index]()

        self.engine.hook_add(unicorn.UC_HOOK_INTR, intr_callback)

        def block_callback(uc, pc, instr_size, user_data):
             
        
        self.bounds = []
        
    def _register(self, name: str) -> int:
        """Translate register name into the tuple
        (u, b, o, s)
        u is the unicorn reg number
        b is the name of full-width base register this is or is part of
        o is start offset within full-width base register
        s is size in bytes

        Arguments:
            register (str): Canonical name of a register.

        Returns:
            The Unicorn constant corresponding to the given register name.
        """

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
        return None

    def read_register_label(self, name: str) -> typing.Optional[str]:        
        (_, base_reg, offset, size) = self._register(name)
        ls = set([])
        if base_reg in self.label:
            for i in range(offset, offset+size):                
                if i in self.label[base_reg]:
                    ls.add(self.label[base_reg][i])
        return ":".join(list(ls))
        
    def read_register(self, name: str) -> int:
        return self.read_register_content(name)    

    def write_register_content(self, name: str, content: int) -> None:
        if value is None:
            logger.debug(f"ignoring register write to {name} - no value")
            return
        (reg, base_reg, offset, size) = self._register(name)
        self.engine.reg_write(reg, value)        
        if base_reg not in self.initialized_registers:
            self.initialized_registers[base_reg] = {}
        for o in range(offset, offset+size):
            self.initialized_registers[base_reg].add(o)
        logger.debug(f"set register {name}={value}")

    def write_register_type(
        self, name: str, typ: typing.Optional[typing.Any] = None
    ) -> None:
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
        return None
    
    def read_memory_type(self, address: int, size: int) -> typing.Optional[typing.Any]:
        return None
    
    def read_memory_label(self, address: int, size: int) -> typing.Optional[str]:
        ls = set([])
        for a in range(address, address+size):
            addr_key = f"{address:x}"
            if addr_key in self.label:
                ls.add(self.label[addr_key])
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
        pass
        
    def write_memory_label(
        self, address: int, size:int, label: typing.Optional[str] = None
    ) -> None:
        for a in range(address, address+size):
            self.label[f"{address:x}"] = label            
        
    def write_memory(self, address: int, content: bytes) -> None:
        self.write_memory_content(address, content)
        
    def hook_instruction(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        self.code_hooks[address] = (function, False)

    def hook_function(
        self, address: int, function: typing.Callable[[Emulator], None]
    ) -> None:
        self.code_hooks[address] = (function, True)

    def hook_memory_read(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int, bytes],
    ) -> None:
        for address in range(start, end+1):
            self.memory_read_hookss[address] = function

    def hook_memory_write(
        self,
        start: int,
        end: int,
        function: typing.Callable[[Emulator, int, int], bytes],
    ) -> None:
        for address in range(start, end+1):
            self.memory_write_hookss[address] = function
            
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

    def hook_interrupts(self, function: typing.Callable[[Emulator, int], None]):
        self.interrupts_hook = function

    def hook_interrupt(self, intno: int, function: typing.Callable[[Emulator], None]):
        self.interrupt_hook[intno] = function

    # Note:
    # inherit from Emulator these
    # def bounds 
    # def add_exit_point
        
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

    def _check(self) -> None:
        # check if its ok to begin emulating
        
        # you are required to have set program counter in order to emulate
        (_, base_name, offset, size)  = self._register("pc")
        if base_name not in self.initialized_registers or len(self.initialized_registers[base_name]) != size:
            raise exceptions.ConfigurationError(
                "pc not initialized, emulation cannot start"
            )

        # an exit point is also required
        if len(self.exit_points) == 0:
            raise exceptions.ConfigurationError(
                "at least one exit point must be set, emulation cannot start"
            )

    def step_instruction(self) -> bool:
        self._check()

        pc = self.read_register("pc")

        code = self.read_memory(pc, 15)  # longest possible instruction
        if code is None:            
            assert False, "impossible state"
        (instr, disas) = self.disassemble(code, pc, 1)

        logger.info(f"single step at 0x{pc:x}: {disas}")

        try: 
            # unicorn requires one exit point so just use first
            self.engine.emu_start(pc, self.exit_point[0], count=1)
        except unicorn.UcError as e:            
            logger.warn(f"emulation stopped - reason: {e}")
            self._error(e, "exec")

        pc = self.read_register("pc")

        if pc in self.exit_points:
            return True
        
        # check if we are at a hook point before checking if in bounds
        for entry in self.hooks.keys():
            if pc == entry:
                return False

        for bound in self.bounds:
            if pc in bound:
                return False

        # done with emulation
        return True
        
    def step_block(self) -> None:
        
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
