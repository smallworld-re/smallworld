from __future__ import annotations

import logging
import sys
import threading
import typing
from enum import Enum

import capstone
import claripy
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

        # NOTE: if there is ANY error in the thread panda code (typos) it will just die...
        # be careful in callbacks
        # If we want to support repeated panda instances we need to make this a subprocess, not thread

        def __init__(self, manager, thread_state):
            super().__init__(daemon=True)
            self.manager = manager
            self.machdef = PandaMachineDef.for_platform(self.manager.platform)
            self.state = thread_state
            self.panda = None
            self.hook_return = None

        # Functions to update state, this prob should be changed
        def setup_state(self, cpu):
            self.manager.cpu = cpu

        def update_state(self, cpu, pc):
            self.manager.cpu = cpu
            self.manager.pc = pc

        def get_panda_args_from_machdef(self):
            panda_args = []

            if hasattr(self.machdef, "machine"):
                panda_args.extend(["-M", self.machdef.machine])
            else:
                panda_args.extend(["-M", "configurable"])

            if hasattr(self.machdef, "cpu"):  # != "":
                panda_args.extend(["-cpu", self.machdef.cpu])

            panda_args.extend(["-nographic"])
            # At some point we can send something in that only supports singlestep?
            # panda_args.extend(["singlestep"])
            return panda_args

        def run(self):
            panda_args = self.get_panda_args_from_machdef()

            self.panda = pandare.Panda(self.machdef.panda_arch, extra_args=panda_args)

            @self.panda.cb_after_machine_init
            def setup(cpu):
                print("Panda: setting up state")
                self.setup_state(cpu)
                self.signal_and_wait()

            @self.panda.cb_insn_translate
            def should_run_on_insn(env, pc):
                return True

            @self.panda.cb_insn_exec
            def on_insn(cpu, pc):
                # PowerPC pc move pc to end of instr
                # so we need to do some stuff to fix that
                if self.machdef.panda_arch == "ppc":
                    pc = pc - 4  # DONT BLAME ME, BLAME ALEX H AND ME :)
                self.update_state(cpu, pc)

                if pc in self.manager._exit_points:
                    # stay here until i say die
                    print("\ton_insn: exit")
                    self.state = PandaEmulator.ThreadState.EXIT
                    self.signal_and_wait()
                elif self.state == PandaEmulator.ThreadState.RUN:
                    # keep going until the end
                    print("\ton_insn: run")
                elif self.state == PandaEmulator.ThreadState.STEP:
                    # stop and wait for me
                    print("\ton_insn: step")
                    self.signal_and_wait()
                elif self.state == PandaEmulator.ThreadState.BLOCK:
                    # keep going until the end
                    print("\ton_insn: block")

                print(f"Panda: on_insn: {hex(pc)}, {self.state}")
                # Check if our pc is in bounds; if not stop
                if (
                    not self.manager._bounds.is_empty()
                    and not self.manager._bounds.contains_value(pc)
                ):
                    print(f"Panda: {pc} out of bounds")
                    self.state = PandaEmulator.ThreadState.EXIT
                    self.signal_and_wait()

                # Always call hooked code first
                if self.manager.all_instructions_hook:
                    self.manager.all_instructions_hook(self.manager)

                if cb := self.manager.is_instruction_hooked(pc):
                    cb(self.manager)

                if cb := self.manager.is_function_hooked(pc):
                    cb(self.manager)
                    # Mimic a platform-specific "return" instruction.
                    if (
                        self.manager.platform.architecture
                        == platforms.Architecture.X86_32
                    ):
                        # i386: pop a 4-byte value off the stack
                        sp = self.manager.read_register("esp")
                        ret = int.from_bytes(
                            self.manager.read_memory(sp, 4),
                            self.manager.platform.byteorder.value,
                        )
                        self.manager.write_register("esp", sp + 4)
                    elif (
                        self.manager.platform.architecture
                        == platforms.Architecture.X86_64
                    ):
                        # amd64: pop an 8-byte value off the stack
                        sp = self.manager.read_register("rsp")
                        ret = int.from_bytes(
                            self.manager.read_memory(sp, 8),
                            self.manager.platform.byteorder.value,
                        )
                        self.manager.write_register("rsp", sp + 8)
                    elif (
                        self.manager.platform.architecture
                        == platforms.Architecture.AARCH64
                        or self.manager.platform.architecture
                        == platforms.Architecture.ARM_V5T
                        or self.manager.platform.architecture
                        == platforms.Architecture.ARM_V6M
                        or self.manager.platform.architecture
                        == platforms.Architecture.ARM_V6M_THUMB
                        or self.manager.platform.architecture
                        == platforms.Architecture.ARM_V7A
                        or self.manager.platform.architecture
                        == platforms.Architecture.ARM_V7M
                        or self.manager.platform.architecture
                        == platforms.Architecture.ARM_V7R
                        or self.manager.platform.architecture
                        == platforms.Architecture.POWERPC32
                        or self.manager.platform.architecture
                        == platforms.Architecture.POWERPC64
                    ):
                        # aarch64, arm32, powerpc and powerpc64: branch to register 'lr'
                        ret = self.manager.read_register("lr")
                    elif (
                        self.manager.platform.architecture
                        == platforms.Architecture.MIPS32
                        or self.manager.platform.architecture
                        == platforms.Architecture.MIPS64
                    ):
                        # mips32 and mips64: branch to register 'ra'
                        ret = self.manager.read_register("ra")
                    else:
                        raise exceptions.ConfigurationError(
                            "Don't know how to return for {self.manager.platform.architecture}"
                        )

                    self.manager.write_register("pc", ret)

                # Now, if we for some reason have a different pc
                # then the one that is set for us, break out of this
                # This would be from changing eip in a hook
                # print(f"Panda: {pc}, {self.manager.pc}")
                # print(self.manager.read_register('pc'))
                # if self.manager.read_register("pc") != pc:
                if self.manager.pc != pc:
                    self.panda.libpanda.cpu_loop_exit_noexc(cpu)

                if not self.manager.current_instruction():
                    # report error if function hooking is enabled?
                    pass
                print(f"\t{self.manager.current_instruction()}")
                self.hook_return = pc + self.manager.current_instruction().size

                return True

            # Used for stepping over blocks
            @self.panda.cb_start_block_exec(enabled=True)
            def on_block(cpu, tb):
                self.update_state(cpu, tb.pc)
                if (
                    self.state == PandaEmulator.ThreadState.BLOCK
                    or self.state == PandaEmulator.ThreadState.SETUP
                ):
                    print(f"Panda: on_block: {tb}, {self.state}")
                    # We need to pause on the next block and wait
                    self.signal_and_wait()

            # Used for hooking mem reads
            @self.panda.cb_virt_mem_before_read(enabled=True)
            def on_read(cpu, pc, addr, size):
                print(f"\ton_read: {addr}")
                orig_data = self.panda.virtual_memory_read(self.manager.cpu, addr, size)
                if self.manager.all_reads_hook:
                    val = self.manager.all_reads_hook(
                        self.manager, addr, size, orig_data
                    )
                    if val:
                        self.manager.write_memory(addr, val)
                        orig_data = val
                if cb := self.manager.is_memory_read_hooked(addr):
                    val = cb(self.manager, addr, size, orig_data)
                    if val:
                        self.manager.write_memory(addr, val)

            # Used for hooking mem writes
            @self.panda.cb_virt_mem_before_write(enabled=True)
            def on_write(cpu, pc, addr, size, buf):
                print(f"\ton_write: {hex(addr)}")
                byte_val = bytes([buf[i] for i in range(size)])

                if self.manager.all_writes_hook:
                    self.manager.all_writes_hook(self.manager, addr, size, byte_val)

                if cb := self.manager.is_memory_write_hooked(addr):
                    cb(self.manager, addr, size, byte_val)

            @self.panda.cb_before_handle_interrupt(enabled=True)
            def on_interrupt(cpu, intno):
                print(f"\ton_interrupt: {intno}")
                # First if all interrupts are hooked, run that function
                if self.manager.all_interrupts_hook:
                    self.manager.all_interrupts_hook(self.manager)
                # Then run interrupt specific function
                if cb := self.manager.is_interrupt_hooked(intno):
                    cb(self.manager)

            @self.panda.cb_before_handle_exception(enabled=True)
            def on_exception(cpu, exception_index):
                print(
                    f"Panda for help: you are hitting an exception at {exception_index}."
                )

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
        if name == "pc" or name == self.panda_thread.machdef.panda_reg("pc"):
            return self.panda_thread.panda.arch.get_pc(self.cpu)

        if not self.panda_thread.machdef.check_panda_reg(name):
            raise exceptions.UnsupportedRegisterError(
                f"Panda doesn't support register {name} for {self.platform}"
            )
        name = self.panda_thread.machdef.panda_reg(name)

        try:
            return self.panda_thread.panda.arch.get_reg(self.cpu, name)
        except:
            raise exceptions.AnalysisError(f"Failed reading {name} (id: {name})")

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

        if name == "pc" or name == self.panda_thread.machdef.panda_reg("pc"):
            # This is my internal pc
            self.pc = content
            self.panda_thread.panda.arch.set_pc(self.cpu, content)
            return

        if not self.panda_thread.machdef.check_panda_reg(name):
            raise exceptions.UnsupportedRegisterError(
                f"Panda doesn't support register {name} for {self.platform}"
            )

        name = self.panda_thread.machdef.panda_reg(name)
        try:
            self.panda_thread.panda.arch.set_reg(self.cpu, name, content)
        except:
            raise exceptions.AnalysisError(f"Failed writing {name} (id: {name})")

        logger.debug(f"set register {name}={content}")

    def read_memory_content(self, address: int, size: int) -> bytes:
        if size > sys.maxsize:
            raise ValueError(f"{size} is too large (max: {sys.maxsize})")

        return self.panda_thread.panda.virtual_memory_read(self.cpu, address, size)

    def map_memory(self, address: int, size: int) -> None:
        def page_down(address):
            return address // self.PAGE_SIZE

        def page_up(address):
            return (address + self.PAGE_SIZE - 1) // self.PAGE_SIZE

        logger.info(
            f"map_memory:asking for mapping at {hex(address)}, size {hex(size)}"
        )
        # Translate an addressi + size to a page range
        if page_down(address) == page_down(address + size):
            region = (page_down(address), page_up(address + size) + 1)
        else:
            region = (page_down(address), page_up(address + size))

        logger.info(f"map_memory: Page range: {region}")

        # Get the missing pages first. Those are the ones we want to map
        missing_range = self.mapped_pages.get_missing_ranges(region)

        # Map in those pages and change the memory mapping
        # Whatever you do map just map a page size or above
        logger.info(f"Mapping memory {missing_range} page(s).")
        for start_page, end_page in missing_range:
            page_size = end_page - start_page
            logger.info(
                f"Mapping at {hex(start_page * self.PAGE_SIZE)} in panda of size {hex(page_size * self.PAGE_SIZE)}"
            )
            self.panda_thread.panda.map_memory(
                f"{start_page * self.PAGE_SIZE}",
                page_size * self.PAGE_SIZE,
                start_page * self.PAGE_SIZE,
            )
        # Make sure we add our new region to our mapped_pages
        self.mapped_pages.add_range(region)

    def get_memory_map(self) -> typing.List[typing.Tuple[int, int]]:
        return list(self.mapped_pages.ranges)

    def write_memory_content(
        self, address: int, content: typing.Union[bytes, claripy.ast.bv.BV]
    ) -> None:
        # Should we type check, if content isnt bytes mad?
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

        # FIXME: MIPS64's physical memory space already has contents.
        # The upper 2**32 bytes of a MIPS64 device is reserved for MMIO.
        # attempting to store stuff there will almost certainly not do what you want.
        # This would go away if we figured out how to emulate virtual memory.
        if self.platform.architecture == platforms.Architecture.MIPS64:
            if address >= 2**32 or (address + len(content)) >= 2**32:
                logger.error(
                    f"Attempting to write to {hex(address)} - {hex(address + len(content))} on MIPS64"
                )
                logger.error("This strays into reserved MMIO memory; please don't.")
                raise exceptions.EmulationError("Write to MIPS64 MMIO space")

        self.panda_thread.panda.physical_memory_write(address, content)

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
            raise exceptions.ConfigurationError(
                "at least one exit point must be set, emulation cannot start"
            )
        if self.panda_thread.state == self.ThreadState.EXIT:
            logger.debug("stopping emulation at exit point")
            raise exceptions.EmulationBounds

    def run(self) -> None:
        self.check()
        logger.info(f"starting emulation at {hex(self.pc)}")
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
        if self.panda_thread.state == self.ThreadState.SETUP:
            # Move past setup
            self.signal_and_wait()

        pc = self.pc
        code = self.read_memory(pc, 15)  # longest possible instruction
        if code is None:
            assert False, "impossible state"
        (instr, disas) = self.disassemble(code, pc, 1)

        logger.info(f"block step at 0x{pc:x}: {disas}")

        self.panda_thread.state = self.ThreadState.BLOCK
        self.signal_and_wait()

    def step_instruction(self) -> None:
        self.check()

        if (
            self.panda_thread.state == self.ThreadState.SETUP
            or self.panda_thread.state == self.ThreadState.BLOCK
        ):
            # Move past setup or block
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
