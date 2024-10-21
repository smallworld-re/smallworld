from __future__ import annotations

import logging
import sys
import threading
import typing
from enum import Enum

import capstone
import pandare

from ... import exceptions, platforms, utils
from .. import emulator, hookable
from .machdefs import PandaMachineDef

logger = logging.getLogger(__name__)


class PandaEmulator(
    emulator.Emulator,
    hookable.QInstructionHookable,
    hookable.QFunctionHookable,
    hookable.QMemoryReadHookable,
    hookable.QMemoryWriteHookable,
    hookable.QInterruptHookable,
):
    """An emulator for the Panda emulation engine.

    Arguments:
        arch: Architecture ID string
        mode: Mode ID string
        byteorder: Byteorder

    """

    description = "This is a smallworld class encapsulating the Panda emulator."
    name = "smallworld's-panda"
    version = "0.0"

    PAGE_SIZE = 0x1000

    class ThreadState(Enum):
        SETUP = 1
        RUN = 2
        STEP = 3
        BLOCK = 4
        EXIT = 5

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
            self.machdef = PandaMachineDef.for_platform(self.manager.platform)
            self.state = thread_state
            self.panda = None

        # Functions to update state, this prob should be changed
        def setup_state(self, cpu):
            self.manager.cpu = cpu

        def update_state(self, cpu, pc):
            self.manager.cpu = cpu
            self.manager.pc = pc

        def run(self):
            panda_args = ["-M", "configurable", "-nographic"]  # "-singlestep"]

            if self.machdef.panda_cpu_str != "":
                panda_args.extend(["-cpu", self.machdef.panda_cpu_str])

            self.panda = pandare.Panda(
                self.machdef.panda_arch_str, extra_args=panda_args
            )

            @self.panda.cb_after_machine_init
            def setup(cpu):
                print("Panda: setting up state")
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
                self.update_state(cpu, pc)

                if pc in self.manager._exit_points:
                    # stay here until i say die
                    print("on_insn: exit")
                    # print(self.manager.read_register("r0"))
                    self.state = PandaEmulator.ThreadState.EXIT
                    self.signal_and_wait()
                    # gracefully (enough) exit here
                elif self.state == PandaEmulator.ThreadState.RUN:
                    # keep going until the end
                    print("on_insn: run")
                elif self.state == PandaEmulator.ThreadState.STEP:
                    # stop and wait for me
                    print("on_insn: step")
                    self.signal_and_wait()
                elif self.state == PandaEmulator.ThreadState.BLOCK:
                    # keep going until the end
                    print("on_insn: block")

                print(f"Panda: on_insn: {hex(pc)}, {self.state}")
                # Check if our pc is in bounds; if not stop
                if (
                    not self.manager._bounds.is_empty()
                    and self.manager._bounds.find_range(pc) is None
                ):
                    print(f"Panda: {pc} out of bounds")
                    self.state = PandaEmulator.ThreadState.EXIT
                    self.signal_and_wait()

                # Always call hooked code first
                if f := self.manager.is_instruction_hooked(pc):
                    f(self.manager)

                # Now, if we for some reason have a different pc
                # then the one that is set for us, break out of this
                # This would be from changing eip in a hook
                # print(f"Panda: {pc}, {self.manager.pc}")
                # print(self.manager.read_register('pc'))
                # if self.manager.read_register("pc") != pc:
                if self.manager.pc != pc:
                    self.panda.libpanda.cpu_loop_exit_noexc(cpu)

                print(f"on_insn: done {self.state}")

                return True

            # Used for stepping over blocks
            @self.panda.cb_start_block_exec(enabled=False)
            def on_block(cpu, tb):
                self.update_state(cpu, tb.pc)
                print(f"Panda: on_block: {tb}, {self.state}")
                # We need to pause on the next block and wait
                self.signal_and_wait()

            # Used for hooking mem reads
            @self.panda.cb_virt_mem_before_read(enabled=True)
            def on_read(cpu, pc, addr, size):
                print(self.manager)
                if rng := self.manager.is_memory_read_hooked(addr):
                    self.manager.memory_read_hooks[rng](self.manager, addr, size)
                print(f"on_read: {addr}")

            # TODO: Untested
            # Used for hooking mem writes
            @self.panda.cb_virt_mem_before_write(enabled=True)
            def on_write(cpu, pc, addr, size, buf):
                # print(f"on_write: {pc}")
                if rng := self.manager.is_memory_write_hooked(addr):
                    # TODO: the type of buf is <class '_cffi_backend._CDataBase'>
                    # how do i translate this to bytes?
                    self.manager.memory_write_hooks[rng](
                        self.manager, addr, size, bytes()
                    )

            # TODO: Untested
            @self.panda.cb_before_handle_interrupt(enabled=False)
            def on_interrupt(cpu, intno):
                # First if all interrupts are hooked, run that function
                if self.manager.all_interrupts_hook:
                    self.manager.all_interrupts_hook(self.manager)
                # Then run interrupt specific function
                if self.manager.is_interrupt_hooked(intno):
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

    def __init__(self, platform: platforms.Platform):
        super().__init__(platform=platform)

        self.PAGE_SIZE = 0x1000
        self.platform = platform

        # Emulator variables
        self.mapped_pages = utils.RangeCollection()

        # Thread/Main sync variables
        self.condition = threading.Condition()
        self.run_panda = False
        self.run_main = False

        # Thread communication variables
        self.cpu = None
        self.pc: int = 0

        self.panda_thread = self.PandaThread(self, self.ThreadState.SETUP)
        self.panda_thread.start()

        self.disassembler = capstone.Cs(
            self.panda_thread.machdef.cs_arch, self.panda_thread.machdef.cs_mode
        )
        self.disassembler.detail = True

        # Wait until panda is up and ready
        with self.condition:
            while not self.run_main:
                self.condition.wait()
            # Clear the event for the next iteration
            self.run_main = False

    def read_register_content(self, name: str) -> int:
        # If we are reading a "pc" reg, refer to actual pc reg
        if name == "pc":
            name = self.panda_thread.machdef.pc_reg

        if name == self.panda_thread.machdef.pc_reg:
            return self.panda_thread.machdef.panda_arch.get_pc(self.cpu)

        if not self.panda_thread.machdef.check_panda_reg(name):
            raise exceptions.UnsupportedRegisterError(
                f"Panda doesn't support register {name} for {self.platform}"
            )
        name = self.panda_thread.machdef.panda_reg(name)

        try:
            return self.panda_thread.machdef.panda_arch.get_reg(self.cpu, name)
        except:
            raise exceptions.AnalysisError(f"Failed reading {name} (id: {name})")

    def write_register_content(self, name: str, content: typing.Optional[int]) -> None:
        if content is None:
            logger.debug(f"ignoring register write to {name} - no value")
            return

        if name == "pc":
            name = self.panda_thread.machdef.pc_reg

        # This is my internal pc
        if name == self.panda_thread.machdef.pc_reg:
            self.pc = content
            self.panda_thread.machdef.panda_arch.set_pc(self.cpu, content)
            return

        if not self.panda_thread.machdef.check_panda_reg(name):
            logger.warn(f"Panda doesn't support register {name} for {self.platform}")
            return

        self.panda_thread.machdef.check_panda_reg(name)
        print(f"setting {name}")
        self.panda_thread.machdef.panda_arch.set_reg(self.cpu, name, content)

        logger.debug(f"set register {name}={content}")

    def read_memory_content(self, address: int, size: int) -> bytes:
        if size > sys.maxsize:
            raise ValueError(f"{size} is too large (max: {sys.maxsize})")

        return self.panda_thread.panda.virtual_memory_read(self.cpu, address, size)

    def map_memory(self, size: int, address: typing.Optional[int] = None) -> int:
        def page(address):
            return address // self.PAGE_SIZE


        if address is not None:
            print(f"map_memory: mapping at {hex(address)}, size {hex(size)}")
            # Translate an addressi + size to a page range
            region = (page(address), page(address + size) + 1)

            # Get the missing pages first. Those are the ones we want to map
            missing_range = self.mapped_pages.get_missing_ranges(region)

            # Map in those pages and change the memory mapping
            # Whatever you do map just map a page size or above
            print(
                f"Mapping memory {missing_range} page(s) original {size} and {address}."
            )
            for start_page, end_page in missing_range:
                page_size = end_page - start_page
                print(
                    f"Mapping at {hex(start_page*self.PAGE_SIZE)} in panda of size {page_size * self.PAGE_SIZE}"
                )
                self.panda_thread.panda.map_memory(
                    f"{start_page*self.PAGE_SIZE}",
                    page_size * self.PAGE_SIZE,
                    start_page * self.PAGE_SIZE,
                )
            # Make sure we add our new region to our mapped_pages
            self.mapped_pages.add_range(region)
            return address
        else:
            # TODO: map a region if we have no address provided
            raise NotImplementedError("Dynamic mapping not yet supported")

    def write_memory_content(self, address: int, content: bytes) -> None:
        # Should we type check, if content isnt bytes mad?
        if content is None:
            raise ValueError(f"{self.__class__.__name__} requires concrete state")

        if len(content) > sys.maxsize:
            raise ValueError(f"{len(content)} is too large (max: {sys.maxsize})")

        if not len(content):
            raise ValueError("memory write cannot be empty")

        # self.map_memory(len(bytes(content)), address)
        # content = content[::-1]
        #print(f"write_memory: {content}")
        self.panda_thread.panda.physical_memory_write(address, content)
        print(
            self.panda_thread.panda.virtual_memory_read(self.cpu, address, len(content))
        )

        logger.debug(f"wrote {len(content)} bytes to 0x{address:x}")

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
        pc = self.pc
        code = self.read_memory(pc, 15)
        if code is None:
            raise AssertionError("invalid state")
        for i in self.disassembler.disasm(code, pc):
            return i

    def check(self) -> None:
        if len(self._exit_points) == 0:
            # TODO warn here
            raise exceptions.ConfigurationError(
                "no exitpoint provided, emulation cannot start"
            )
        if self.panda_thread.state == self.ThreadState.EXIT:
            logger.debug("stopping emulation at exit point")
            raise exceptions.EmulationBounds

        if self.pc is None:
            raise exceptions.ConfigurationError(
                "no entry provided, emulation cannot start"
            )

        return

    def run(self) -> None:
        self.check()
        logger.info(f"starting emulation at 0x{self.pc}")
        self.panda_thread.state = self.ThreadState.RUN
        self.signal_and_wait()
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
        # TODO disable this callback when appropriate
        self.panda_thread.panda.enable_callback("on_block")

        # if self.panda_thread.state == self.ThreadState.SETUP:
        #    self.signal_and_wait()

        self.panda_thread.state = self.ThreadState.BLOCK
        self.signal_and_wait()

    def step_instruction(self) -> None:
        self.check()

        if self.panda_thread.state == self.ThreadState.SETUP:
            # Move past setup
            self.panda_thread.state = self.ThreadState.STEP
            self.signal_and_wait()

        self.panda_thread.state = self.ThreadState.STEP

        pc = self.pc
        print(f"Step: reading register {pc}")

        code = self.read_memory(pc, 15)  # longest possible instruction
        if code is None:
            assert False, "impossible state"
        (instr, disas) = self.disassemble(code, pc, 1)

        logger.info(f"single step at 0x{pc:x}: {disas}")

        # We can run now and wait at next instr;
        self.signal_and_wait()
        return

    def __repr__(self) -> str:
        return f"PandaEmulator(platform={self.platform})"
