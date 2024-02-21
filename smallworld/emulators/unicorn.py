import logging
import math
import typing
import sys

import capstone as cs
import unicorn
from unicorn import unicorn_const as uc

from .. import exceptions
from .. import unicorn_exceptions
from . import emulator

logger = logging.getLogger(__name__)


class UnicornEmulator(emulator.Emulator):
    """An emulator for the Unicorn emulation engine.

    Arguments:
        arch: Unicorn architecture constant.
        mode: Unicorn mode constant.
    """

    ARCHITECTURES = {"x86": unicorn.UC_ARCH_X86}

    MODES = {"32": unicorn.UC_MODE_32, "64": unicorn.UC_MODE_64}

    I386_REGISTERS = {
        "eax": unicorn.x86_const.UC_X86_REG_EAX,
        "ebx": unicorn.x86_const.UC_X86_REG_EBX,
        "ecx": unicorn.x86_const.UC_X86_REG_ECX,
        "edx": unicorn.x86_const.UC_X86_REG_EDX,
        "esi": unicorn.x86_const.UC_X86_REG_ESI,
        "edi": unicorn.x86_const.UC_X86_REG_EDI,
        "ebp": unicorn.x86_const.UC_X86_REG_EBP,
        "esp": unicorn.x86_const.UC_X86_REG_ESP,
        "eip": unicorn.x86_const.UC_X86_REG_EIP,
        "cs": unicorn.x86_const.UC_X86_REG_CS,
        "ds": unicorn.x86_const.UC_X86_REG_DS,
        "es": unicorn.x86_const.UC_X86_REG_ES,
        "fs": unicorn.x86_const.UC_X86_REG_FS,
        "gs": unicorn.x86_const.UC_X86_REG_GS,
        "eflags": unicorn.x86_const.UC_X86_REG_EFLAGS,
        "cr0": unicorn.x86_const.UC_X86_REG_CR0,
        "cr1": unicorn.x86_const.UC_X86_REG_CR1,
        "cr2": unicorn.x86_const.UC_X86_REG_CR2,
        "cr3": unicorn.x86_const.UC_X86_REG_CR3,
        "cr4": unicorn.x86_const.UC_X86_REG_CR4,
    }

    AMD64_REGISTERS = {
        "rax": unicorn.x86_const.UC_X86_REG_RAX,
        "rbx": unicorn.x86_const.UC_X86_REG_RBX,
        "rcx": unicorn.x86_const.UC_X86_REG_RCX,
        "rdx": unicorn.x86_const.UC_X86_REG_RDX,
        "r8": unicorn.x86_const.UC_X86_REG_R8,
        "r9": unicorn.x86_const.UC_X86_REG_R9,
        "r10": unicorn.x86_const.UC_X86_REG_R10,
        "r11": unicorn.x86_const.UC_X86_REG_R11,
        "r12": unicorn.x86_const.UC_X86_REG_R12,
        "r13": unicorn.x86_const.UC_X86_REG_R13,
        "r14": unicorn.x86_const.UC_X86_REG_R14,
        "r15": unicorn.x86_const.UC_X86_REG_R15,
        "rsi": unicorn.x86_const.UC_X86_REG_RSI,
        "rdi": unicorn.x86_const.UC_X86_REG_RDI,
        "rbp": unicorn.x86_const.UC_X86_REG_RBP,
        "rsp": unicorn.x86_const.UC_X86_REG_RSP,
        "rip": unicorn.x86_const.UC_X86_REG_RIP,
        "rflags": unicorn.x86_const.UC_X86_REG_RFLAGS,
    }

    REGISTERS = {
        unicorn.UC_ARCH_X86: {
            unicorn.UC_MODE_32: I386_REGISTERS,
            unicorn.UC_MODE_64: {**I386_REGISTERS, **AMD64_REGISTERS},
        }
    }

    CAPSTONE_ARCH_MAP = {unicorn.UC_ARCH_X86: cs.CS_ARCH_X86}

    CAPSTONE_MODE_MAP = {
        unicorn.UC_MODE_32: cs.CS_MODE_32,
        unicorn.UC_MODE_64: cs.CS_MODE_64,
    }

    def __init__(self, arch: str, mode: str):
        super().__init__()

        arch = arch.lower()
        if arch not in self.ARCHITECTURES:
            raise ValueError(f"unsupported architecture: {arch}")
        self.arch = self.ARCHITECTURES[arch]

        mode = mode.lower()
        if mode not in self.MODES:
            raise ValueError(f"unsupported processor mode: {mode}")
        self.mode = self.MODES[mode]

        if self.arch not in self.REGISTERS:
            raise ValueError("unsupported architecture")

        if self.mode not in self.REGISTERS[self.arch]:
            raise ValueError("unsupported mode for current architecture")

        self.memory: typing.Dict[typing.Tuple[int, int], int] = {}

        self.entrypoint: typing.Optional[int] = None
        self.exitpoint: typing.Optional[int] = None

        self.single_stepping = False

        self.engine = unicorn.Uc(self.arch, self.mode)
        self.disassembler = cs.Cs(
            self.CAPSTONE_ARCH_MAP[self.arch], self.CAPSTONE_MODE_MAP[self.mode]
        )
        self.disassembler.detail = True

    def register(self, name: str) -> int:
        """Translate register name into Unicorn const.

        Arguments:
            register (str): Canonical name of a register.

        Returns:
            The Unicorn constant corresponding to the given register name.
        """

        name = name.lower()

        # support some generic register references
        if name == "pc":
            if self.arch == unicorn.UC_ARCH_X86:
                if self.mode == unicorn.UC_MODE_32:
                    name = "eip"
                elif self.mode == unicorn.UC_MODE_64:
                    name = "rip"
                else:
                    raise NotImplementedError(
                        f"no idea how to get pc for x86 mode [{self.mode}]"
                    )
            else:
                raise NotImplementedError(
                    f"no idea how to get pc for arch [{self.arch}]"
                )

        try:
            return self.REGISTERS[self.arch][self.mode][name]
        except KeyError:
            raise ValueError(f"unknown or unsupported register '{name}'")

    def read_register(self, name: str) -> int:
        return self.engine.reg_read(self.register(name))

    def write_register(self, name: str, value: typing.Optional[int]) -> None:
        if value is None:
            raise ValueError(f"{self.__class__.__name__} requires concrete state")

        self.engine.reg_write(self.register(name), value)

        logger.debug(f"set register {name}={value}")

    def read_memory(self, address: int, size: int) -> typing.Optional[bytes]:
        # UC_ERR_ARG: Size can't be greater than INT_MAX
        if size > sys.maxsize: 
            raise ValueError(f"size of memory {size} is larger than sys.maxsize.")

        try:
            return self.engine.mem_read(address, size)
        except unicorn.unicorn.UcError:
            logger.warn(f"attempted to read uninitialized memory at 0x{address:x}")
            return None

    PAGE_SIZE = 0x1000

    def write_memory(self, address: int, value: typing.Optional[bytes]) -> None:
        if value is None:
            raise ValueError(f"{self.__class__.__name__} requires concrete state")

        for key, mapping in self.memory.items():
            if address > key[0] and address < key[1]:
                # Overlaping writes are currently unsupported.
                #
                # It shouldn't be too difficult to support this, just check the
                # size of the mapping and allocate the difference if necessary.
                # For now though, we raise an error.

                raise ValueError(
                    "write overlaps with existing memory mapping (currently unsupported)"
                )

        # Handles UC_ERR_ARG 

        # Size cannot be 0
        if not len(value): 
            raise ValueError("memory region cannot have 0 bytes")

        # Address must be aligned to a page size
        if address & (self.PAGE_SIZE - 1) != 0: 
            raise ValueError(f"address {hex(address)} needs to be a aligned to a page size {hex(self.PAGE_SIZE)}")

        # Address can't wrap around

        # Size can't be greater than INT_MAX
        if len(value) > sys.maxsize: 
            raise ValueError(f"size of memory {len(value)} is larger than sys.maxsize.")

        pages = math.ceil(len(value) / self.PAGE_SIZE)
        allocation = pages * self.PAGE_SIZE

        self.engine.mem_map(address, allocation)

        self.memory[address, address + allocation] = True

        logger.debug(f"new memory map 0x{address:x}[{allocation}]")

        self.engine.mem_write(address, bytes(value))

        logger.debug(f"wrote {len(value)} bytes to 0x{address:x}")

    def load(self, code: emulator.Code) -> None:
        if code.base is None:
            raise ValueError(f"base address is required: {code}")

        self.write_memory(code.base, code.image)

        if code.entry is not None:
            self.entrypoint = code.entry
            if self.entrypoint < code.base or self.entrypoint > code.base + len(
                code.image
            ):
                raise ValueError(
                    "Entrypoint is not in code: 0x{self.entrypoint:x} vs (0x{code.base:x}, 0x{code.base + len(code.image):x})"
                )
        else:
            self.entrypoint = code.base

        if code.exits:
            self.exitpoint = list(code.exits)[0]
        else:
            self.exitpoint = code.base + len(code.image)

        self.write_register("pc", self.entrypoint)

        logger.info(f"loaded code (size: {len(code.image)} B) at 0x{code.base:x}")

    def disassemble(
        self, code: bytes, count: typing.Optional[int] = None
    ) -> typing.Tuple[typing.List[cs.CsInsn], str]:
        # TODO: annotate that offsets are relative
        #
        # We don't know what the base address is at disassembly time - so we
        # just set it to 0. This means relative address arguments aren't
        # correctly calculated - we should annotate that relative arguments are
        # relative e.g., with a "+" or something.
        base = 0x0
        instructions = self.disassembler.disasm(code, base)

        disassembly = []
        insns = []
        for i, instruction in enumerate(instructions):
            if count is not None and i >= count:
                break
            insns.append(instruction)
            disassembly.append(f"{instruction.mnemonic} {instruction.op_str}")

        return (insns, "\n".join(disassembly))

    def check(self) -> None:
        if self.entrypoint is None:
            raise exceptions.ConfigurationError(
                "no entrypoint provided, emulation cannot start"
            )
        if self.exitpoint is None:
            raise exceptions.ConfigurationError(
                "no exitpoint provided, emulation cannot start"
            )

    def run(self) -> None:
        self.check()

        logger.info(
            f"starting emulation at 0x{self.entrypoint:x} until 0x{self.exitpoint:x}"
        )
        try:
            self.engine.emu_start(self.entrypoint, self.exitpoint)
        except unicorn.UcError as e:
            logger.warn(f"emulation stopped - reason: {e}")
            self.raise_exception_with_details(e)
            #raise exceptions.EmulationError(e)

        logger.info("emulation complete")

    def step(self) -> bool:
        self.check()

        pc = self.read_register("pc")

        code = self.read_memory(pc, 15)  # longest possible instruction
        if code is None:
            assert False, "impossible state"
        (instr, disas) = self.disassemble(code, 1)

        logger.info(f"single step at 0x{pc:x}: {disas}")

        try:
            self.engine.emu_start(pc, self.exitpoint, count=1)
        except unicorn.UcError as e:
            logger.warn(f"emulation stopped - reason: {e}")
            self.raise_exception_with_details(e)
            #raise exceptions.EmulationError(e)

        pc = self.read_register("pc")
        if self.entrypoint is None or self.exitpoint is None:
            assert False, "impossible state"
        if pc >= self.exitpoint or pc < self.entrypoint:
            # inform caller that we are done
            return True

        return False
    


    def get_insn_rw(self, insn : cs.CsInsn) -> tuple: 
        """Get register names read from and written to for capstone instruction."""

        (regs_read, regs_written) = insn.regs_access()
        r_read = {insn.reg_name(r) for r in regs_read}
        r_written = {insn.reg_name(r) for r in regs_written}
        return (r_read, r_written)
    
    def get_operand_details(self, op, insn : cs.CsInsn) -> dict:
        """Get operand details (REG, MEM, IMM) for a capstone instruction op"""

        # x86 instructions with capstone
        # REG -> operand is a register
        # MEM -> operand is a memory reference
        # IMM -> operand is an immediate value 
        op_map = {}

        if op.type == cs.x86.X86_OP_REG:
            reg = insn.reg_name(op.value.reg)
            value = self.emulator.read_register(reg)
            op_map['REG'] = { reg : value }
        # (register base, register index, offset)
        elif op.type == cs.x86.X86_OP_MEM:
            base, index, offset, base_value, index_value = "", "", 0, 0, 0
            p = {}
            if op.value.mem.base != 0: # this is a ptr 
                base = insn.reg_name(op.value.mem.base)
                base_value = self.emulator.read_register(base)
                p[base] = base_value
            if op.value.mem.index != 0:
                index = insn.reg_name(op.value.mem.index)
                index_value = self.read_register(index)
                p[index] = index_value
            if op.value.mem.disp != 0:
                offset = op.value.mem.disp
                p["offset"] = offset
            op_map['MEM'] = p 
        # value 
        elif op.type == cs.x86.X86_OP_IMM:
            op_map['IMM'] = op.value.imm
        return op_map
    
    def get_exception_rw_details(self, insn : cs.CsInsn, is_read : bool) -> dict: 
        """Get details for unicorn emulation exceptions: UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED"""

        print(type(insn))
        (regs_read, regs_written) = self.get_insn_rw(insn)
        regs = regs_read if is_read else regs_written 

        # Read/write can either be an operand or implied 
        details = {}
        op_read, op_written = None, None
        if len(insn.operands) == 1: 
            op_read = insn.operands[0]
        elif len(insn.operands) == 2:
            op_written = insn.opernads[0]
            op_read = insn.operands[1]
        op = op_read if is_read else op_written

        if op and op.type == cs.x86.X86_OP_MEM: 
            details = self.get_operand_details(op, insn)
        else: 
            for reg in regs:
                details['REG'] = {reg : self.read_register(reg)} 
        
        print(details)
        return details


    def raise_exception_with_details(self, e: unicorn.UcError) -> dict: 
        pc = self.read_register("pc") 
        code = self.read_memory(pc, 16) 
        if code is None:
            assert False, "impossible state"
        (insns, disas) = self.disassemble(code, 1)
        insn = insns[0]

        if e.args[0] == uc.UC_ERR_READ_UNMAPPED:
            details = self.get_exception_rw_details(insn, True)
        elif e.args[0] == uc.UC_ERR_WRITE_UNMAPPED:
            details = self.get_exception_rw_details(insn, False) 
        elif e.args[0] == uc.UC_ERR_FETCH_UNMAPPED: 
            # this is the pc address unmapped
            details['REG'] = {"pc" : pc} 
        elif e.args[0] == uc.UC_ERR_INSN_INVALID: 
            # bytes at pc are bad
            details['BYTES']  = {"pc" : code}

        raise unicorn_exceptions.UnicornEmulationError(e.args[0], insn, pc, details) 



    def __repr__(self) -> str:
        return f"Unicorn(mode={self.mode}, arch={self.arch})"
