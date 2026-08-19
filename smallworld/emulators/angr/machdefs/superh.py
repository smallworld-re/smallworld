import functools
import typing

import angr
import archinfo
import pypcode

from ....platforms import Architecture, Byteorder
from ....platforms.defs.superh import (
    SH2A_FLOAT_ARGUMENT_REGISTERS,
    SH2A_INTEGER_ARGUMENT_REGISTERS,
    SH2A_PROGRAM_COUNTER_REGISTER,
    SH2A_REGISTER_ALIASES,
    SH2A_RETURN_ADDRESS_REGISTER,
    SH2A_RETURN_VALUE_REGISTER,
    SH2A_STATUS_REGISTER,
)
from .machdef import GhidraMachineDef

SH2A_PCODE_LANGUAGE = "SuperH:BE:32:SH-2A"


@functools.lru_cache(maxsize=None)
def pcode_arch(language: str) -> archinfo.arch.Arch:
    """One shared ``ArchPcode`` per sleigh language.

    ``archinfo.ArchPcode.__init__`` re-runs ``pypcode.Arch.enumerate()`` and
    rebuilds the whole register table every time - roughly 8 ms per call, and
    archinfo does not memoize it.  The ``SimCC`` classes here and in
    ``superh4.py`` only ever read from ``ARCH``, so sharing one object per
    language turns six constructions into three.  That cost is paid during
    ``import smallworld``, for every user on every platform, because
    ``machdefs/__init__.py`` imports these modules eagerly.
    """
    return archinfo.ArchPcode(language)


# ---------------------------------------------------------------------------
# Linux/SH syscalls under angr
# ---------------------------------------------------------------------------
#
# SuperH's only trap instruction is `trapa #imm`.  Sleigh models it as machine
# state rather than as an event, so out of the box nothing about it reaches
# `hook_syscall`/`hook_syscalls`:
#
#   * `SuperH4.sinc` lowers it to the `TrapAlways` userop, which becomes a
#     CALLOTHER.  SmallWorld's angr backend rejects those outright, so SH-4
#     `trapa` used to raise EmulationError("CALLOTHER emulation not currently
#     supported").
#   * `superh.sinc` (SH-2A) lowers it in full, as a vector dispatch: push `sr`,
#     push `inst_next`, then `call [*(vbr + imm*4)]`.  That lifts to a plain
#     `Ijk_Call` with a memory-derived target, so with `vbr` unconstrained angr
#     silently dropped the successor and the run "completed" having executed
#     nothing.
#
# Neither is a syscall as far as angr is concerned: `angr/engines/pcode/lifter.py`
# derives the jumpkind purely from the terminating p-code opcode and can only
# produce Ijk_Boring / Ijk_Call / Ijk_Ret / Ijk_NoDecode.  Sleigh p-code has no
# syscall opcode at all, so *no* pcode-lifted architecture gets `Ijk_Sys_syscall`
# from the lifter, and `HookableSimOS.syscall()` is only consulted on that
# jumpkind.
#
# The fix is the one `machdefs/xtensa.py` already uses for Xtensa's `syscall`
# userop, and it is established SmallWorld-side machinery for pcode arches
# rather than a new mechanism: override `successors()`, find the trap in the
# lifted block, truncate the block there, and set the jumpkind by hand.  A
# syscall calling convention has to be registered too, because
# `HookableSimOS.syscall()` builds `SyscallHookProcedure(cc=SYSCALL_CC[...])`
# and `SyscallHookProcedure.run()` immediately calls `self.cc.syscall_num()`;
# without a registration `cc` is None and that is an AttributeError.
#
# NOTE (design plan correction): the plan justified having no `successors()`
# override on SuperH on the grounds that SH-2A's sleigh defines only one pcodeop
# (`Sleep_Standby`) and that SH-4's ~11 userops are "none reachable from
# ordinary user code".  `TrapAlways` disproves that last clause: `trapa` is a
# perfectly ordinary instruction and every SH-4 `trapa` hits it.
#
# NOTE (cross-backend semantics): after this change the *same* `trapa #0x10`
# surfaces two different ways depending on the backend - as an **interrupt**
# (number 352 = QEMU's 0x160 EXCP_TRAPA) under PANDA, and as a **syscall** under
# angr.  Both readings are live in the test suite simultaneously: the
# `interrupt` scenario depends on the PANDA one and the `syscall` scenario on
# the angr one.  This is the same shape as amd64, where `int 0x80` is an
# interrupt and `syscall` is a syscall, except that SuperH spells both with one
# instruction and each backend surfaces it through whichever machinery it has.
# It is deliberate, but it is surprising, so: written down.
#
# The register assignment below is not from memory.  It is QEMU's own Linux/SH
# user-mode syscall entry, `linux-user/sh4/cpu_loop.c`:
#
#     case 0x160:
#         env->pc += 2;
#         ret = do_syscall(env, env->gregs[3],
#                          env->gregs[4], env->gregs[5], env->gregs[6],
#                          env->gregs[7], env->gregs[0], env->gregs[1], 0, 0);
#         ...
#         env->gregs[0] = ret;
#
# i.e. number in r3, arguments r4, r5, r6, r7, r0, r1, result in r0, and resume
# two bytes past the trap.
#
# LIMITATION - the trap immediate is deliberately *not* checked.  Linux/SH
# conventionally writes `trapa #0x10`, but `TrapAlways` fires for every
# immediate and SH-2A's vector dispatch is likewise immediate-agnostic, so this
# rewrite treats *any* `trapa` as a syscall.  That matches QEMU, which is the
# reference implementation here: `helper_trapa()` sets exception_index = 0x160
# for every immediate and stashes the immediate in `env->tra` for the guest to
# read, and the dispatch above keys on 0x160 alone with no test on `tra`.
# Gating on `#0x10` would be mechanically easy but would silently fail to fire
# on any binary using another vector, which is worse than being over-broad.  A
# caller that cares can read the immediate itself from the trapping PC.

# Every SuperH instruction that matters here is 16 bits wide; the SH-2A 32-bit
# forms are all in encoding families `trapa` is not part of.
SUPERH_INSN_SIZE = 2

# `SuperH4.sinc`'s `define pcodeop TrapAlways;`, used by `:trapa`.
SUPERH_TRAP_USEROP = "TrapAlways"

# `superh.sinc`'s `:trapa` has no userop, so SH-2A is matched on the mnemonic.
SUPERH_TRAP_MNEMONIC = "trapa"

SUPERH_SYSCALL_NUMBER_REGISTER = "r3"
SUPERH_SYSCALL_ARGUMENT_REGISTERS = ("r4", "r5", "r6", "r7", "r0", "r1")
SUPERH_SYSCALL_RETURN_REGISTER = "r0"


def lift_for_rewrite(state: angr.SimState, kwargs: typing.Dict[str, typing.Any]):
    """Lift the block at ``state``'s PC so it can be inspected and rewritten.

    Mirrors the prologue of :meth:`AngrMachineDef.successors` and of
    ``machdefs/xtensa.py``: exit points are folded into the lift and removed
    from ``kwargs`` (which this mutates), because they end up baked into the
    block handed back to the engine.

    Unlike the Xtensa version this does *not* force ``opt_level=0``.  That line
    is a no-op for pcode arches - ``angr/engines/pcode/lifter.py`` documents
    ``opt_level`` as "Unused by P-Code lifter" - and leaving it unset keeps this
    lift bit-identical to the one the engine would have done on its own.
    """
    assert hasattr(state.scratch, "exit_points")

    if kwargs.get("irsb") is not None:
        # Someone already decided which block to run.
        return kwargs["irsb"]

    if "extra_stop_points" in kwargs:
        exit_points = state.scratch.exit_points | set(kwargs.pop("extra_stop_points"))
    else:
        exit_points = state.scratch.exit_points

    return state.block(extra_stop_points=exit_points, **kwargs).vex


def covers_one_instruction(imark) -> bool:
    """Is this IMARK for a single instruction?

    Sleigh lifts a SuperH branch *together with its delay slot*, and when it does
    it emits one IMARK listing both instruction addresses - measured, for
    `bra 1f; trapa #0x10`:

        IMARK [ram 0x1000, ram 0x1002]
        ... trapa's ops ...
        BRANCH ram 0x1004

    The delay-slot body is emitted before the transfer, so the trap's ops are not
    separable from the branch's and there is no IMARK boundary to truncate at.
    Truncating at the shared IMARK anyway discards the BRANCH: measured on SH-4
    with this check forced true, the syscall fires and the run ends at the exit
    point having *never taken the `bra`*.  Silently ignoring a branch is worse
    than not surfacing the syscall.

    `TRAPA` is a delay-slot-prohibited instruction on SuperH (it raises an illegal
    slot exception there), so valid code never does this - but binutils assembles
    it without complaint, so a hand-written or fuzzed blob can.  Both machdefs
    therefore decline to rewrite such a block and leave the pre-existing
    behaviour in place; measured for `bra 1f; trapa #0x10`, that is the
    unhandled-CALLOTHER error on SH-4 and sleigh's literal vector dispatch on
    SH-2A.  Declining is right rather than merely safe: there is no syscall to
    model, because the architecture faults instead.
    """
    return len(imark.inputs) == 1


def rewrite_as_syscall(irsb, keep: int, next_addr: int) -> None:
    """Turn ``irsb`` into a block that ends in a syscall at ``next_addr``.

    ``keep`` is the number of leading p-code ops to retain: everything up to and
    including the trap instruction's IMARK, and nothing of the trap's own
    semantics.  Ops for *earlier* instructions in the same block must survive -
    the test blob's `mov #4, r3` sets the syscall number, and truncating one op
    too early would leave r3 unwritten.

    ``keep`` must include the trap instruction's own IMARK.  Dropping it - which
    is what a literal port of Xtensa's ``handle_syscall`` does, since there the
    IMARK is always at ``i - 1`` and the trap is always the whole instruction -
    leaves a block with zero ops, and angr then hands the syscall a state whose
    ``_ip`` is still the trap itself.  ``SyscallHookProcedure`` jumps to
    ``state._ip``, so execution returns to the ``trapa`` and loops forever.
    Measured: it hangs, it does not error.
    """
    assert keep > 0, "syscall rewrite must retain the trap's IMARK"
    irsb._ops = irsb._ops[0:keep]
    irsb.next = next_addr
    irsb._size = next_addr - irsb.addr
    # `_instruction_addresses` is `list[int] | None`: `IRSB.extend()` calls
    # `_set_attributes` without it, so a block stitched together from several
    # lifter passes has None here while still carrying the concatenated ops.
    # The SH-2A caller never reaches this on such a block - `extend()` also
    # clears `_disassembly`, which it checks first - but the SH-4 caller keys on
    # a CALLOTHER that survives the concatenation, so guard rather than raise
    # TypeError from inside successor computation.
    if irsb._instruction_addresses is not None:
        irsb._instruction_addresses = [
            addr for addr in irsb._instruction_addresses if addr < next_addr
        ]
    irsb.jumpkind = "Ijk_Sys_syscall"


class SimCCSuperHLinuxSyscall(angr.calling_conventions.SimCCSyscall):
    """Linux/SH syscall convention, per QEMU's ``linux-user/sh4/cpu_loop.c``.

    ``ARCH`` is left None and filled in per language ID by the subclasses that
    get registered, matching ``SimCCXtensaLinuxSyscall``.
    """

    ARG_REGS = list(SUPERH_SYSCALL_ARGUMENT_REGISTERS)
    FP_ARG_REGS: typing.List[str] = []
    RETURN_VAL = angr.calling_conventions.SimRegArg(SUPERH_SYSCALL_RETURN_REGISTER, 4)
    # `archinfo.ArchPcode` synthesizes no `ip_at_syscall`, so angr logs
    # "Handling syscall on arch ... without ip_at_syscall register" and, in its
    # own words, hopes vigorously.  That is benign here: the scratch register
    # only caches the resume address, and `SyscallHookProcedure` jumps to
    # `state._ip`, which `rewrite_as_syscall` already set to the instruction
    # after the trap.
    RETURN_ADDR = angr.calling_conventions.SimRegArg("ip_at_syscall", 4)
    ARCH = None

    @classmethod
    def _match(cls, arch, args, sp_data):
        # Never match by inference; this convention only applies to syscalls.
        return False

    @staticmethod
    def syscall_num(state):
        return getattr(state.regs, SUPERH_SYSCALL_NUMBER_REGISTER)


class SH2AFPUMachineDef(GhidraMachineDef):
    arch = Architecture.SUPERH_SH2A_FPU
    byteorder = Byteorder.BIG
    pcode_language = SH2A_PCODE_LANGUAGE

    # SuperH is a delay-slot ISA, but unlike the VEX-backed MIPS machdefs this
    # one is safe to single-step: sleigh lifts a branch and its delay slot as one
    # unit, emitting the delay-slot semantics before the transfer, so a single
    # step covers both.
    supports_single_step = True

    # `archinfo.ArchPcode` lowercases every sleigh register name, and SH-2A's
    # spec is already lowercase, so this is an identity map apart from the
    # aliases. ArchPcode synthesizes `sp` (onto r15) and `ip` (onto pc) but not
    # `fp`/`ra`/`lr`, so each alias resolves to the architectural register it
    # names rather than relying on that synthesis.
    _registers: typing.Dict[str, str] = {
        # *** General-Purpose Registers ***
        **{f"r{i}": f"r{i}" for i in range(0, 16)},
        **SH2A_REGISTER_ALIASES,
        # *** Control Registers ***
        SH2A_PROGRAM_COUNTER_REGISTER: SH2A_PROGRAM_COUNTER_REGISTER,
        SH2A_STATUS_REGISTER: SH2A_STATUS_REGISTER,
        "pr": "pr",
        "gbr": "gbr",
        "vbr": "vbr",
        "tbr": "tbr",
        "mach": "mach",
        "macl": "macl",
        # *** Floating-Point Registers ***
        **{f"dr{i}": f"dr{i}" for i in range(0, 16, 2)},
        **{f"fr{i}": f"fr{i}" for i in range(0, 16)},
        "fpscr": "fpscr",
        "fpul": "fpul",
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        """Surface `trapa` as a syscall.

        SH-2A needs the disassembly-driven path, not the CALLOTHER-driven one
        SH-4 uses: `superh.sinc` models `trapa` in full rather than delegating to
        a userop, so there is no CALLOTHER to key on.  The mnemonic is matched
        instead, against the disassembly the pcode lifter has already attached
        to the block, and the ops are then truncated at that instruction's IMARK.

        Also note what is being discarded, because it is not nothing: sleigh's
        SH-2A `trapa` pushes `sr` and the return address onto r15 before
        dispatching.  Truncating removes those pushes, so the syscall does not
        leave an exception frame on the stack.  That is the right call for a
        *syscall* hook - a hooked syscall is emulated, not delivered, and
        `SyscallHookProcedure` returns straight to the instruction after the trap
        with no `rte` to unwind the frame - but it does mean this is not a
        faithful model of SH-2A exception entry.
        """
        irsb = lift_for_rewrite(state, kwargs)

        # `PcodeIRSB._disassembly` starts as None and is only filled in on the
        # success path of `angr/engines/pcode/lifter.py`'s translate, and
        # `IRSB.extend()` sets it back to None while keeping the concatenated
        # ops.  So a block can legitimately have ops and no disassembly: either
        # it failed to decode (BadDataError / UnimplError / LowlevelError, in
        # which case its jumpkind is already Ijk_NoDecode and it cannot contain a
        # decodable `trapa`) or it was stitched together from several lifter
        # passes.  Skipping the rewrite is the graceful answer for both - the
        # trap simply is not surfaced as a syscall on such a block - whereas
        # dereferencing None here would turn a clean "undecodable instruction"
        # error into an opaque AttributeError on the hot path.
        disassembly = irsb._disassembly
        if disassembly is None:
            kwargs["irsb"] = irsb
            return super().successors(state, **kwargs)

        # Lowest address is first in execution order within a basic block.  This
        # runs on every executed block, so take the minimum lazily rather than
        # materializing and sorting a list to read element zero.
        trap_addr = min(
            (
                insn.address
                for insn in disassembly.insns
                if insn.mnemonic.strip() == SUPERH_TRAP_MNEMONIC
            ),
            default=None,
        )
        if trap_addr is not None:
            # Retain everything up to and including the trap's own IMARK; see
            # `rewrite_as_syscall` for why the IMARK has to survive.  An IMARK
            # covering several instructions is a delay-slot lift and is skipped
            # outright, per `covers_one_instruction` - which is also why this
            # matches on `inputs[0]` alone rather than searching every input.
            keep = None
            for i, op in enumerate(irsb._ops):
                if op.opcode != pypcode.OpCode.IMARK:
                    continue
                if not covers_one_instruction(op):
                    continue
                if op.inputs[0].offset == trap_addr:
                    keep = i + 1
                    break
            if keep is not None:
                rewrite_as_syscall(irsb, keep, trap_addr + SUPERH_INSN_SIZE)

        kwargs["irsb"] = irsb
        return super().successors(state, **kwargs)


class SimCCSH2AFPU(angr.calling_conventions.SimCC):
    ARG_REGS = list(SH2A_INTEGER_ARGUMENT_REGISTERS)
    FP_ARG_REGS = list(SH2A_FLOAT_ARGUMENT_REGISTERS)
    # Spelled explicitly rather than left to `ArchPcode`: it derives
    # `arch.ret_offset` from the first `<output><pentry>` in the compiler spec,
    # and `superh2a.cspec` lists the float return fr0 ahead of r0.
    RETURN_VAL = angr.calling_conventions.SimRegArg(SH2A_RETURN_VALUE_REGISTER, 4)
    RETURN_ADDR = angr.calling_conventions.SimRegArg(SH2A_RETURN_ADDRESS_REGISTER, 4)
    ARCH = pcode_arch(SH2A_PCODE_LANGUAGE)  # type: ignore


class SimCCSH2AFPULinuxSyscall(SimCCSuperHLinuxSyscall):
    ARCH = pcode_arch(SH2A_PCODE_LANGUAGE)  # type: ignore


angr.calling_conventions.register_default_cc(SH2A_PCODE_LANGUAGE, SimCCSH2AFPU)
angr.calling_conventions.register_syscall_cc(
    SH2A_PCODE_LANGUAGE, "default", SimCCSH2AFPULinuxSyscall
)
