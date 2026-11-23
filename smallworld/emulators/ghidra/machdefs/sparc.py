import typing

from ghidra.program.model.pcode import PcodeOp, Varnode

from ....platforms import Architecture, Byteorder
from ....platforms.defs.sparc import (
    SPARC_FRAME_POINTER_REGISTER,
    SPARC_STACK_POINTER_REGISTER,
    SPARC_WINDOW_REGISTERS,
)
from .machdef import GhidraMachineDef


class SPARC32MachineDef(GhidraMachineDef):
    """Ghidra machine definition for 32-bit SPARC.

    Ghidra's SPARC language keeps the current window in fixed registers and
    implements `save`/`restore` by copying %i/%l to and from a backing bank
    of registers indexed by CWP, with no window limit and no overflow traps.
    That copy has two defects (Ghidra 12.1.2): `save` stores %l3 in %l2's
    slot, and `restore` loads %l7 from %l6's slot, so %l2 and %l7 come back
    wrong after a call.  `pcode_fixes` corrects both.
    """

    arch = Architecture.SPARC32
    byteorder = Byteorder.BIG

    _registers: typing.Dict[str, typing.Optional[str]] = {
        **{name: name for name in SPARC_WINDOW_REGISTERS},
        # Ghidra names r14 and r30 only by their ABI roles.
        SPARC_STACK_POINTER_REGISTER: "sp",
        SPARC_FRAME_POINTER_REGISTER: "fp",
        "sp": "sp",
        "fp": "fp",
        "pc": "PC",
        # Ghidra's sleigh folds each delay slot into its branch's p-code and
        # never reads or writes nPC, so the register would only hold stale
        # values.
        "npc": None,
        "y": "Y",
    }

    fixes_pcode = True

    def _register_name(self, varnode: typing.Optional[Varnode]) -> typing.Optional[str]:
        if varnode is None or not varnode.isRegister():
            return None
        reg = self.language.getRegister(varnode.getAddress(), varnode.getSize())
        return None if reg is None else str(reg.getName()).lower()

    def _window_slot_add(
        self,
        code: typing.Sequence[PcodeOp],
        defs: typing.Dict[int, int],
        address: Varnode,
    ) -> typing.Optional[int]:
        """The index of the op adding a window slot to CWP * window size.

        Walks the computation of a bank address back to `CWP * 16 + slot`,
        the INT_ADD whose second input is the constant slot number.
        """
        pending = [address]
        while pending:
            varnode = pending.pop()
            if not varnode.isUnique() or varnode.getOffset() not in defs:
                continue
            index = defs[varnode.getOffset()]
            op = code[index]
            if op.getOpcode() == PcodeOp.INT_ADD and op.getInput(1).isConstant():
                base = op.getInput(0)
                if base.isUnique() and base.getOffset() in defs:
                    base_op = code[defs[base.getOffset()]]
                    if (
                        base_op.getOpcode() == PcodeOp.INT_MULT
                        and self._register_name(base_op.getInput(0)) == "cwp"
                    ):
                        return index
            pending.extend(op.getInputs())
        return None

    def pcode_fixes(self, code: typing.Sequence[PcodeOp]) -> typing.Dict[int, PcodeOp]:
        # Each local's bank slot is `CWP * 16 + n + 8` for %ln.  Make every
        # store of a local store the register its slot belongs to, and every
        # load of a local read that register's slot.
        fixes: typing.Dict[int, PcodeOp] = {}
        defs: typing.Dict[int, int] = {}
        for index, op in enumerate(code):
            opcode = op.getOpcode()
            if opcode == PcodeOp.STORE:
                name = self._register_name(op.getInput(2))
                if name is not None and name.startswith("l"):
                    slot_index = self._window_slot_add(code, defs, op.getInput(1))
                    if slot_index is not None:
                        want = f"l{code[slot_index].getInput(1).getOffset()}"
                        if want != name:
                            reg = self.language.getRegister(want)
                            fixes[index] = PcodeOp(
                                op.getSeqnum(),
                                opcode,
                                [
                                    op.getInput(0),
                                    op.getInput(1),
                                    Varnode(reg.getAddress(), reg.getMinimumByteSize()),
                                ],
                                None,
                            )
            elif opcode == PcodeOp.LOAD:
                name = self._register_name(op.getOutput())
                if name is not None and name.startswith("l"):
                    slot_index = self._window_slot_add(code, defs, op.getInput(1))
                    if slot_index is not None:
                        slot_op = code[slot_index]
                        want_slot = int(name[1:])
                        if slot_op.getInput(1).getOffset() != want_slot:
                            const = self.language.getAddressFactory().getConstantSpace()
                            fixes[slot_index] = PcodeOp(
                                slot_op.getSeqnum(),
                                slot_op.getOpcode(),
                                [
                                    slot_op.getInput(0),
                                    Varnode(
                                        const.getAddress(want_slot),
                                        slot_op.getInput(1).getSize(),
                                    ),
                                ],
                                slot_op.getOutput(),
                            )

            output = op.getOutput()
            if output is not None and output.isUnique():
                defs[output.getOffset()] = index
        return fixes
