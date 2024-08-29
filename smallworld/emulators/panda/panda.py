from __future__ import annotations

import logging
import sys
import typing

import capstone
import pandare
import threading
from enum import Enum

from ... import exceptions, instructions, state
from .. import emulator
from .machdefs import PandaMachineDef

logger = logging.getLogger(__name__)


class PandaEmulator():
    """An emulator for the Panda emulation engine.

    Arguments:
        arch: Architecture ID string
        mode: Mode ID string
        byteorder: Byteorder

    """
    PAGE_SIZE = 0x1000

    class ThreadState(Enum): 
        SETUP = 1
        RUN = 2
        STEP = 3
        BLOCK = 4


    class PandaThread(threading.Thread):

        # If we want to support both basic block iteration and single step iteration
        # We cannot get pc from state, cpu eip only holds the basic block pc 
        # so we have to transfer eip, we just need to pass it around
        # do we want to support this?
        # we could run in single step mode always? what are the implications of this?
        # you have to tell me IN ADVANCE when you setup whether you want to step or block
        # through things... 
        # other things that are a bit annoying...cb_insn_translate without single step
        # iterates through a "translation" of a  whole "block" of instructions before it 
        # starts executing them, whereas single step would not do that; im not even entirely 
        # sure at this point how its determining the bounds of a block but it definitely has 
        # something to do with mapped memory 

        # NOTE: there are two methods here (1) you can run arbitrary code (without 
        # control flow changes potentially but you should run in single step mode, 
        # (2) running in normal mode, if you try to run code without an "end" to 
        # your bb, it will crash 

        def __init__(self, manager, thread_state):
            super().__init__(daemon=True)
            self.manager = manager
            self.machdef = PandaMachineDef.for_arch(self.manager.arch, self.manager.mode, self.manager.byteorder)
            self.state = thread_state
            self.panda = None

        # Functions to update state, this prob should be changed 
        def setup_state(self, cpu):
            self.manager.cpu = cpu

        def update_state(self, cpu, pc): 
            self.manager.cpu = cpu
            self.manager.pc = pc

        def run(self): 
            panda_args = ["-M", "configurable", "-nographic"] # "-singlestep"] 
            self.panda = pandare.Panda(self.machdef.panda_arch_str, 
                extra_args=panda_args) 

            @self.panda.cb_after_machine_init
            def setup(cpu):
                self.setup_state(cpu)
                self.signal_and_wait()

            # The following two are used for both hooking, single step, and
            # when to stop panda from executing, I would love to be able to 
            # actually use this to not instrument things we don't want but 
            # it runs the ENTIRE BLOCK before it calls anything else
            # ordering -> should_run_on_insn, start_block_exec, on_insn
            # We could potentially instrument by determining ahead of time 
            # but thats a problem also because you dont know which block exit pc
            # lives in so nope.
            @self.panda.cb_insn_translate
            def should_run_on_insn(env, pc):
                return True

            @self.panda.cb_insn_exec
            def on_insn(cpu, pc): 
                print(f"Panda: on_insn: {pc}, {self.state}")
                self.update_state(cpu, pc)

                # Always hook first 
                if pc in self.manager.hooks:
                    self.manager.hooks[pc](self.manager)
                # If we were in SETUP mode, we need to be able to move
                # from setup to here 
                if self.state == PandaEmulator.ThreadState.SETUP: 
                    print("on_insn: setup")
                    self.signal_and_wait()
                elif pc in self.manager.exitpoints: 
                    # stay here until i say die
                    print("on_insn: exit")
                    self.signal_and_wait()
                elif self.state == PandaEmulator.ThreadState.RUN: 
                    # keep going until the end
                    print("on_insn: run")
                elif self.state == PandaEmulator.ThreadState.STEP: 
                    # stop and wait for me 
                    print("on_insn: step")
                    print(cpu.env_ptr.eip)
                    self.signal_and_wait()
                elif self.state == PandaEmulator.ThreadState.BLOCK:
                    # keep going until the end
                    print("on_insn: block")
                print(f"on_insn: done {self.state}")
                return True

            
            # Used for stepping over blocks
            @self.panda.cb_start_block_exec(enabled=False)
            def on_block(cpu, tb): 
                self.update_state(cpu, tb.pc)
                print(f"Panda: on_block: {tb}, {self.state}")
                # We need to pause on the next block and wait
                self.signal_and_wait()

            # TODO: Untested
            # Used for hooking mem reads 
            @self.panda.cb_virt_mem_before_read(enabled=False)
            def on_read(cpu, pc, addr, size):
                print(f"on_read: {pc}")
                import os
                os._exit(0)

            # TODO: Untested
            # Used for hooking mem writes 
            @self.panda.cb_virt_mem_before_write(enabled=False) 
            def on_write(cpu, pc, addr, size): 
                print(f"on_write: {pc}")
                import os
                os._exit(0)

            # TODO: Untested
            @self.panda.cb_before_handle_interrupt(enabled=False) 
            def on_interrupt(cpu, intno): 
                if intno in self.manager.interrupt_hooks: 
                    self.manager.interrupt_hooks[intno](self.manager)

            self.panda.run()

        # This is a blocking call for this thread
        def signal_and_wait(self):
            print("Signaling main to run")
            with self.manager.condition: 
                # Signal that we are done and to run main

                self.manager.run_main = True
                self.manager.condition.notify() 

                # Wait until main tells us to run panda 
                while not self.manager.run_panda: 
                    self.manager.condition.wait()

                # Clear the event for the next iteration
                self.manager.run_panda = False 


    def __init__(self, arch: str, mode: str, byteorder: str, step : bool = False):
        super().__init__()

        self.arch = arch
        self.mode = mode
        self.byteorder = byteorder

        self.PAGE_SIZE = 0x1000

        # Emulator variables
        self.entry: typing.Optional[int] = None
        self.exitpoints : typing.Set[int] = set()
        self.mapped_pages : typing.List[typing.Tuple[int,int]] = []
        self.bounds: typing.List[typing.Tuple[int,int]] = []
        self.hooks : typing.Dict[int, typing.Tuple[typing.Callable[[emulator.Emulator], None], bool]] = {} 

        # Thread/Main sync variables 
        self.condition = threading.Condition()
        self.run_panda = False
        self.run_main = False 

        # Thread communication variables  
        self.cpu = None
        self.pc = None

        self.panda_thread = self.PandaThread(self, self.ThreadState.SETUP)
        self.panda_thread.start()

        self.disassembler = capstone.Cs(self.panda_thread.machdef.cs_arch, 
                self.panda_thread.machdef.cs_mode)
        self.disassembler.detail = True

        with self.condition: 
            # Wait until main tells us to run panda 
            while not self.run_main: 
                self.condition.wait()
            # Clear the event for the next iteration
            self.run_main = False 


    def read_register(self, name: str) -> int:

        self.panda_thread.machdef.check_panda_reg(name)

        try:
            if name == "eip" or name == "pc": 
                return self.panda_thread.machdef.panda_arch.get_pc(self.cpu)
            else:
                return self.panda_thread.machdef.panda_arch.get_reg(self.cpu, name)
        except:
            raise exceptions.AnalysisError(f"Failed reading {name} (id: {reg})")

    def write_register(
        self,
        name: str,
        value: typing.Optional[int],
        label: typing.Optional[typing.Any] = None,
    ) -> None:

        if value is None:
            logger.debug(f"ignoring register write to {name} - no value")
            return

        self.panda_thread.machdef.check_panda_reg(name)

        if name == "eip" or name == "pc": 
            self.panda_thread.machdef.panda_arch.set_pc(self.cpu, value)
        else: 
            self.panda_thread.machdef.panda_arch.set_reg(self.cpu, name, value)

        logger.debug(f"set register {name}={value}")


    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        if size > sys.maxsize:
            raise ValueError(f"{size} is too large (max: {sys.maxsize})")

        try:
            return self.panda_thread.panda.virtual_memory_read(self.cpu, address, size)
        except unicorn.unicorn.UcError:
            logger.warn(f"attempted to read uninitialized memory at 0x{address:x}")
            return None

    # TODO
    def map_memory(self, 
            size: int,
            address: Optional[int]) -> int: 

        def page(address): 
            return address // self.PAGE_SIZE

        # Lets find our missing pages 
        region = (page(address), page(address+size) + 1)
        pages = region[1] - region[0]
        start_page, end_page = region
        prev_end = start_page 
        missing_range = []
        for start, end in self.mapped_pages:
            if start > prev_end: 
                missing_range.append((prev_end, start)) 
            prev_end = max(prev_end, end) 
            if end_page > prev_end: 
                missing_range.append((prev_end, end_val))

        print(missing_range)
        print(self.mapped_pages)

        # Whatever you do map just map a page size or above 
        self.panda_thread.panda.map_memory(f"{address}", pages * self.PAGE_SIZE, address)
        print(f"Mapping memory {pages} page(s) original {size} and {address}.")


    def write_memory(
        self,
        address: int,
        value: typing.Optional[bytes],
        label: typing.Optional[typing.Dict[int, typing.Any]] = None,
    ) -> None:
        if value is None:
            raise ValueError(f"{self.__class__.__name__} requires concrete state")

        if len(value) > sys.maxsize:
            raise ValueError(f"{len(value)} is too large (max: {sys.maxsize})")

        if not len(value):
            raise ValueError("memory write cannot be empty")

        print("WRITING MEM")
        print(value)
        print(address)
        self.map_memory(len(bytes(value)), address) 
        self.panda_thread.panda.physical_memory_write(address, bytes(value))
        print(self.panda_thread.panda.virtual_memory_read(self.cpu, address, len(value)))

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

    def hook_instruction(self, address: int, 
            function: typing.Callable[[emulator.Emulator], None],) -> None:

        self.hooks[address] = function

        # TODO: Ensure that the address is mapped 

        # Enable the panda callback if not enabled 
        if not self.panda_thread.panda.is_callback_enabled("on_insn"): 
            self.panda_thread.panda.enable_callback("on_insn") 


    def hook_memory_write(self, start: int, end: int, 
            function: Callable[[emulator.Emulator, int, int], bytes]): 
        pass

    def hook_memory_write(self, start: int, end: int, 
            function: Callable[[emulator.Emulator, int, int, bytes], None]): 
        pass

    def hook_interrupts(self, function: Callable[[emulator.Emulator, int], None]): 
        pass

    def hook_interrupt(self, interrupt: int, function: Callable[[emulator.Emulator], None]): 
        self.interrupt_hooks[interrupt] = function
        self.panda_thread.panda.enable_callback("on_interrupt")

    def add_bound(self, bounds, bound): 
        import bisect
        i = bisect.bisect_left(bounds, (start, end))
        new_bounds = []

        # Handle the case where the bound falls to the left of i 
        if i > 0 and start <= bounds[i-1][1]: 
            i -= 1 
            start = min(start, bounds[i][0])
            end = max(end, bounds[i][1]) 
        new_bounds.extend(bounds[:i])

        # Merge with all right bounds until we are the min right bound
        while i < len(bounds) and bounds[i][0] <= end: 
            start = min(stard, bounds[i][0])
            end = max(end, bounds[i][1]) 
            i += 1

        # Add the merged bound 
        new_bounds.append((start,end))
        
        # Add the remaining non-overlapping bounds
        new_bounds.extend(bounds[i:])

        return new_bounds

    def bound(self, start: int, end: int): 

        self.bounds = self.add_bound(self.bounds, start, end)

    def exitpoint(self, address : int): 
        self.exitpoints.add(address)

    def hook_memory(
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

        if len(self.exitpoints) == 0: 
            raise exceptions.ConfigurationError(
                "no exitpoint provided, emulation cannot start"
            )
        # This is to know we have run setup already so to enter
        # the actual callbacks now for running
        print(self.pc)

        return
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
        self.panda_thread.state = self.ThreadState.RUN
        self.signal_and_wait()

        logger.info(f"starting emulation at 0x{self.pc:x} until 0x{self.exit:x}")
        return
        try:
            self.engine.emu_start(self.entry, self.exit)
        except unicorn.UcError as e:
            logger.warn(f"emulation stopped - reason: {e}")
            logger.warn("for more details, run emulation in single step mode")
            raise exceptions.EmulationError(e)

        logger.info("emulation complete")

    def signal_and_wait(self) -> None:
        print("Main signaling panda to run")
        with self.condition: 
            # Signal that we are done and to run panda 
            self.run_panda = True
            self.condition.notify() 

            # Wait until main tells us to run panda 
            while not self.run_main: 
                self.condition.wait()

            # Clear the event for the next iteration
            self.run_main = False 


    def step_block(self) -> None: 

        self.check() 

        # If we just came from setting up, we need to get into the 
        # on_block callback, but also run it once 
        self.panda_thread.panda.enable_callback("on_block") 
        
        if self.panda_thread.state == self.ThreadState.SETUP:
            self.signal_and_wait()

        self.panda_thread.state = self.ThreadState.BLOCK
        self.signal_and_wait()

    def step(self) -> None:
        self.step_instruction() 

    def step_instruction(self) -> None:
        self.check()

        if self.panda_thread.state == self.ThreadState.SETUP:
            self.signal_and_wait()
            
        self.panda_thread.state = self.ThreadState.STEP

        pc = self.pc 
        print(f"Step: reading register {pc}")

        code = self.read_memory(pc, 15)  # longest possible instruction
        if code is None:
            assert False, "impossible state"
        (instr, disas) = self.disassemble(code, pc, 1)

        logger.info(f"single step at 0x{pc:x}: {disas}")

        # We can run now; 
        self.signal_and_wait()
        return

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
