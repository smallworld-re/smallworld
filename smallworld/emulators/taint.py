"""Emulator-agnostic dynamic taint tracking.

This module implements concrete, byte-granular taint propagation that can be
driven by any emulator implementing the shared hooking API (instruction hook,
memory-read hook, memory-write hook) -- i.e. the QEMU-family concrete backends
(Unicorn, PANDA, Styx).

Taint sources are seeded from state labels: when an emulator is constructed with
``taint=True``, a labeled register or memory value (see
:meth:`smallworld.state.Value.set_label`) becomes a taint source named by its
label.  As instructions execute, the set of source labels that reached each
register/memory byte is propagated.  On extraction the accumulated taint is
surfaced via :meth:`smallworld.state.Value.get_taint`.

The tracker is intentionally decoupled from any specific engine: it reads the
current instruction (via the emulator's ``current_instruction`` helper if
present, otherwise by disassembling bytes it reads from the emulator), maps
operands to register byte ranges via the platform's register-alias table, and
maintains its own shadow maps.  It never mutates emulated content -- the
memory-read hook always returns ``None``.
"""

import logging
import typing

import capstone

logger = logging.getLogger(__name__)

# Mnemonics whose "self" form (identical register operands) unconditionally
# produce zero regardless of input, and therefore clear taint on the output.
_CLEARING_MNEMONICS = {
    "xor",
    "sub",
    "pxor",
    "xorps",
    "xorpd",
    "eor",
    "veor",
}

# Maximum instruction length to read when disassembling (x86 worst case).
_MAX_INSN_BYTES = 15

# Fallback register-access inference, used only for architectures where capstone
# reports neither regs_access() nor per-operand access flags (notably MIPS). The
# RISC convention is that the first register operand is the destination; these
# mnemonics are the exceptions that write no general register.
_NO_REG_WRITE_MNEMONICS = {
    # stores
    "sb",
    "sh",
    "sw",
    "swl",
    "swr",
    "sc",
    "scd",
    "sd",
    "sdl",
    "sdr",
    "swc1",
    "sdc1",
    "swc2",
    "sdc2",
    "cache",
    "pref",
    # branches / jumps / traps that write no general register
    "b",
    "beq",
    "bne",
    "blez",
    "bgtz",
    "bltz",
    "bgez",
    "beqz",
    "bnez",
    "beql",
    "bnel",
    "blezl",
    "bgtzl",
    "bltzl",
    "bgezl",
    "bc1t",
    "bc1f",
    "j",
    "jr",
    "nop",
    "sync",
    "teq",
    "tge",
    "tlt",
    "tne",
    "break",
    "syscall",
}

# Mnemonics that write the return-address register.
_LINK_MNEMONICS = {"jal", "jalr", "bal", "bgezal", "bltzal", "bgezall", "bltzall"}


class TaintTracker:
    """Concrete byte-granular taint propagation for a hookable emulator.

    Arguments:
        emulator: The host emulator.  Must expose ``platform``,
            ``read_register``/``read_memory`` and the ``hook_instructions`` /
            ``hook_memory_reads`` / ``hook_memory_writes`` hooking API.
        taint_addresses: When ``True``, taint also propagates through addresses
            (a value loaded via a tainted pointer/index becomes tainted, and a
            store's destination bytes inherit the address registers' taint).
    """

    def __init__(self, emulator: typing.Any, taint_addresses: bool = False):
        # Imported lazily to avoid an import cycle: this module is only loaded
        # when taint tracking is enabled (well after package initialization).
        from ..instructions import Instruction, RegisterOperand
        from ..platforms import PlatformDef, RegisterAliasDef

        self._emu = emulator
        self._taint_addresses = taint_addresses

        self._pdef = PlatformDef.for_platform(emulator.platform)
        self._pc_register = self._pdef.pc_register
        self._Instruction = Instruction
        self._RegisterOperand = RegisterOperand
        self._RegisterAliasDef = RegisterAliasDef

        self._md = capstone.Cs(self._pdef.capstone_arch, self._pdef.capstone_mode)
        self._md.detail = True

        # Shadow taint state.
        #   registers: base register name -> {byte offset -> set of source labels}
        #   memory:    absolute address   -> set of source labels
        self._reg_taint: typing.Dict[str, typing.Dict[int, typing.Set[str]]] = {}
        self._mem_taint: typing.Dict[int, typing.Set[str]] = {}

        # Per-instruction working state.  Register writes have no native hook,
        # so they are recorded here and applied one instruction later (once the
        # instruction's memory reads have also been observed) -- and flushed at
        # run end via finalize().
        self._cur_read_taint: typing.Set[str] = set()
        self._cur_mem_read_taint: typing.Set[str] = set()
        self._cur_addr_taint: typing.Set[str] = set()
        self._pending_writes: typing.Optional[
            typing.List[typing.Tuple[str, int, int]]
        ] = None
        self._pending_clear: bool = False

    # -- installation ---------------------------------------------------------

    def install(self) -> None:
        """Register propagation callbacks on the host emulator."""
        self._emu.hook_instructions(self.on_instruction)
        self._emu.hook_memory_reads(self.on_memory_read)
        self._emu.hook_memory_writes(self.on_memory_write)

    def finalize(self) -> None:
        """Flush the last executed instruction's deferred register writes.

        Emulation stops *before* executing the exit/out-of-bounds instruction,
        so the final executed instruction's register writes are never flushed by
        a subsequent instruction hook.  Callers must invoke this at run end.
        """
        self._flush_pending()

    # -- register byte-range helpers -----------------------------------------

    def _reg_range(self, name: str) -> typing.Optional[typing.Tuple[str, int, int]]:
        """Resolve a register name to ``(base_register, start_byte, end_byte)``.

        Returns ``None`` for registers not present in the platform table (e.g.
        flags or segment registers), which are simply not tracked.
        """
        rd = self._pdef.registers.get(name)
        if rd is None:
            rd = self._pdef.registers.get(name.lower())
        if rd is None:
            rd = self._pdef.registers.get(name.lower().lstrip("$"))
        if rd is None:
            return None
        if isinstance(rd, self._RegisterAliasDef):
            return (rd.parent, rd.offset, rd.offset + rd.size)
        return (rd.name, 0, rd.size)

    def _get_reg_range_taint(self, name: str) -> typing.Set[str]:
        rng = self._reg_range(name)
        if rng is None:
            return set()
        base, start, end = rng
        by_byte = self._reg_taint.get(base)
        if not by_byte:
            return set()
        out: typing.Set[str] = set()
        for offset in range(start, end):
            labels = by_byte.get(offset)
            if labels:
                out |= labels
        return out

    def _set_reg_bytes(self, base: str, start: int, end: int, taint: typing.Set[str]):
        by_byte = self._reg_taint.setdefault(base, {})
        for offset in range(start, end):
            if taint:
                by_byte[offset] = set(taint)
            else:
                by_byte.pop(offset, None)

    def _set_reg_range_taint(self, name: str, taint: typing.Set[str]) -> None:
        rng = self._reg_range(name)
        if rng is None:
            return
        base, start, end = rng
        self._set_reg_bytes(base, start, end, taint)

    # -- memory helpers -------------------------------------------------------

    def _get_mem_range_taint(self, address: int, size: int) -> typing.Set[str]:
        out: typing.Set[str] = set()
        for addr in range(address, address + size):
            labels = self._mem_taint.get(addr)
            if labels:
                out |= labels
        return out

    def _set_mem_range_taint(
        self, address: int, size: int, taint: typing.Set[str]
    ) -> None:
        for addr in range(address, address + size):
            if taint:
                self._mem_taint[addr] = set(taint)
            else:
                self._mem_taint.pop(addr, None)

    # -- public taint API (delegated to by the emulator) ----------------------

    def read_register_taint(self, name: str) -> typing.Set[str]:
        return self._get_reg_range_taint(name)

    def write_register_taint(self, name: str, taint: typing.Set[str]) -> None:
        self._set_reg_range_taint(name, taint)

    def read_memory_taint(self, address: int, size: int) -> typing.Set[str]:
        return self._get_mem_range_taint(address, size)

    def write_memory_taint(
        self, address: int, size: int, taint: typing.Set[str]
    ) -> None:
        self._set_mem_range_taint(address, size, taint)

    def seed_register(self, name: str, label: str) -> None:
        """Mark a register (or sub-register) as a taint source."""
        self._set_reg_range_taint(name, {label})

    def seed_memory(self, address: int, size: int, label: str) -> None:
        """Mark a memory range as a taint source."""
        self._set_mem_range_taint(address, size, {label})

    # -- propagation ----------------------------------------------------------

    def _base_of(self, name: str) -> typing.Optional[str]:
        rng = self._reg_range(name)
        return rng[0] if rng is not None else None

    def _mem_operand_regs(self, operand: typing.Any) -> typing.List[str]:
        """Base/index register names used to compute a memory operand's address."""
        regs = []
        for attr in ("base", "index"):
            reg = getattr(operand, attr, None)
            if reg and reg != "None":
                regs.append(reg)
        return regs

    def _register_accesses(
        self, insn: typing.Any
    ) -> typing.Tuple[typing.List[str], typing.List[str]]:
        """Return ``(read_register_names, written_register_names)``.

        Uses capstone's ``regs_access()`` (accurate reads-vs-writes for every
        architecture, including implicit accesses), and falls back to the
        operand abstraction if it is unavailable.
        """
        cs_insn = insn._instruction
        # 1. Preferred: capstone regs_access() (accurate, includes implicit regs
        #    and distinguishes reads from writes). Supported for x86/ARM/AArch64.
        try:
            regs_read, regs_written = cs_insn.regs_access()
            reads = [cs_insn.reg_name(r) for r in regs_read]
            writes = [cs_insn.reg_name(w) for w in regs_written]
            return [r for r in reads if r], [w for w in writes if w]
        except Exception:
            pass
        # 2. Per-operand access flags present: the operand abstraction is exact.
        if any(getattr(o, "access", None) for o in cs_insn.operands):
            reads = [
                op.name for op in insn.reads if isinstance(op, self._RegisterOperand)
            ]
            writes = [
                op.name for op in insn.writes if isinstance(op, self._RegisterOperand)
            ]
            return reads, writes
        # 3. No access info at all (e.g. capstone's MIPS): infer from operand
        #    order. Without this, every operand would be treated as written,
        #    spuriously tainting source registers.
        return self._infer_register_accesses(cs_insn)

    def _infer_register_accesses(
        self, cs_insn: typing.Any
    ) -> typing.Tuple[typing.List[str], typing.List[str]]:
        reg_ops = [o for o in cs_insn.operands if o.type == capstone.CS_OP_REG]
        reads = [cs_insn.reg_name(o.reg) for o in reg_ops]
        reads = [r for r in reads if r]
        mnemonic = cs_insn.mnemonic.lower().split(".")[0]
        writes: typing.List[str] = []
        if mnemonic in _LINK_MNEMONICS:
            writes = ["ra"]
        elif mnemonic not in _NO_REG_WRITE_MNEMONICS and reg_ops:
            # RISC convention: the first register operand is the destination.
            first = cs_insn.reg_name(reg_ops[0].reg)
            if first:
                writes = [first]
        return reads, writes

    def _is_clearing_idiom(self, insn: typing.Any) -> bool:
        cs_insn = insn._instruction
        mnemonic = cs_insn.mnemonic.lower()
        base_mnemonic = mnemonic.split(".")[0]
        if (
            base_mnemonic not in _CLEARING_MNEMONICS
            and mnemonic not in _CLEARING_MNEMONICS
        ):
            return False
        reg_ops = [o for o in cs_insn.operands if o.type == capstone.CS_OP_REG]
        return len(reg_ops) >= 2 and all(o.reg == reg_ops[0].reg for o in reg_ops)

    def _flush_pending(self) -> None:
        if self._pending_writes is None:
            return
        if self._pending_clear:
            total: typing.Set[str] = set()
        else:
            total = self._cur_read_taint | self._cur_mem_read_taint
        for base, start, end in self._pending_writes:
            self._set_reg_bytes(base, start, end, total)
        self._pending_writes = None

    def _read_insn_bytes(self, emu: typing.Any, pc: int) -> typing.Optional[bytes]:
        for size in (_MAX_INSN_BYTES, 8, 4, 2, 1):
            try:
                return emu.read_memory(pc, size)
            except Exception:
                continue
        return None

    def _decode(self, emu: typing.Any) -> typing.Optional[typing.Any]:
        cs_insn = None
        getter = getattr(emu, "current_instruction", None)
        if getter is not None:
            try:
                cs_insn = getter()
            except Exception:
                cs_insn = None
        if cs_insn is None:
            try:
                pc = emu.read_register(self._pc_register)
            except Exception:
                return None
            code = self._read_insn_bytes(emu, pc)
            if not code:
                return None
            try:
                cs_insn = next(self._md.disasm(code, pc))
            except Exception:
                return None
        if cs_insn is None:
            return None
        try:
            return self._Instruction.from_capstone(cs_insn)
        except Exception:
            return None

    def on_instruction(self, emu: typing.Any) -> None:
        """Instruction hook: flush the previous instruction, prime the current."""
        try:
            # The previous instruction has finished; apply its register writes.
            self._flush_pending()

            self._cur_read_taint = set()
            self._cur_mem_read_taint = set()
            self._cur_addr_taint = set()
            self._pending_writes = None
            self._pending_clear = False

            insn = self._decode(emu)
            if insn is None:
                return

            # Registers used only to compute a memory address (base/index of a
            # dereferenced operand) are "address registers". In the default
            # data-flow-only mode they do NOT contribute data taint to the
            # instruction's outputs; capstone still reports them as register
            # reads, so we must exclude them explicitly.
            addr_reg_names: typing.List[str] = []
            for operand in list(insn.reads) + list(insn.writes):
                if not isinstance(operand, self._RegisterOperand):
                    addr_reg_names.extend(self._mem_operand_regs(operand))
            addr_bases = {self._base_of(n) for n in addr_reg_names} - {None}

            addr_taint: typing.Set[str] = set()
            for name in addr_reg_names:
                addr_taint |= self._get_reg_range_taint(name)

            # Register read/write sets come from capstone's regs_access(), which
            # accurately reports explicit and implicit accesses and, crucially,
            # distinguishes reads from writes even on architectures that don't
            # populate per-operand access flags (e.g. MIPS).
            reg_reads, reg_writes = self._register_accesses(insn)

            read_taint: typing.Set[str] = set()
            for name in reg_reads:
                is_address_reg = self._base_of(name) in addr_bases
                if is_address_reg and not self._taint_addresses:
                    # Address-computation register: not a data input here.
                    continue
                read_taint |= self._get_reg_range_taint(name)

            pending: typing.List[typing.Tuple[str, int, int]] = []
            for name in reg_writes:
                rng = self._reg_range(name)
                if rng is not None:
                    pending.append(rng)

            self._cur_read_taint = read_taint
            self._cur_addr_taint = addr_taint
            self._pending_writes = pending if pending else None
            self._pending_clear = self._is_clearing_idiom(insn)
        except Exception:
            # Taint tracking must never break emulation.
            logger.debug("taint instruction hook failed", exc_info=True)
            self._pending_writes = None

    def on_memory_read(
        self, emu: typing.Any, address: int, size: int, content: bytes
    ) -> typing.Optional[bytes]:
        """Memory-read hook: accumulate the taint flowing into this instruction."""
        try:
            taint = self._get_mem_range_taint(address, size)
            if self._taint_addresses:
                taint = taint | self._cur_addr_taint
            self._cur_mem_read_taint |= taint
        except Exception:
            logger.debug("taint memory-read hook failed", exc_info=True)
        # Never override the value the guest reads.
        return None

    def on_memory_write(
        self, emu: typing.Any, address: int, size: int, content: bytes
    ) -> None:
        """Memory-write hook: taint the destination bytes from this instruction."""
        try:
            taint = self._cur_read_taint | self._cur_mem_read_taint
            if self._taint_addresses:
                taint = taint | self._cur_addr_taint
            self._set_mem_range_taint(address, size, taint)
        except Exception:
            logger.debug("taint memory-write hook failed", exc_info=True)


__all__ = ["TaintTracker"]
