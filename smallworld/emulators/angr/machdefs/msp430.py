import typing

import angr
import pypcode

from ....exceptions import EmulationError
from ....platforms import Architecture, Byteorder
from .machdef import GhidraMachineDef

# There is one pcodeop, bcd_add.
# No.

# Angr doesn't have a syscall calling convention for msp430.
# I don't think one exists.


class MSP430AbsMachineDef(GhidraMachineDef):
    byteorder = Byteorder.LITTLE

    _registers = {
        "pc": "pc",
        "r0": "pc",
        "sp": "sp",
        "r1": "sp",
        "sr": "sr",
        "r2": "sr",
        # NOTE: cg1 isn't accessible directly.
        # Accessing the constant generator registers is somewhat meaningless,
        # so this isn't a hardship.
        "cg1": "",
        "cg2": "r3",
        "r3": "r3",
        "r4": "r4",
        "r5": "r5",
        "r6": "r6",
        "r7": "r7",
        "r8": "r8",
        "r9": "r9",
        "r10": "r10",
        "r11": "r11",
        "r12": "r12",
        "r13": "r13",
        "r14": "r14",
        "r15": "r15",
    }

    def successors(self, state: angr.SimState, **kwargs) -> typing.Any:
        # Inject exit points here.
        assert hasattr(state.scratch, "exit_points")

        if "extra_stop_points" in kwargs:
            exit_points = state.scratch.exit_points | set(kwargs["extra_stop_points"])
            del kwargs["extra_stop_points"]
        else:
            exit_points = state.scratch.exit_points

        # Fetch or compute the IR block for our state
        if "irsb" in kwargs and kwargs["irsb"] is not None:
            # Someone's already specified an IR block.
            irsb = kwargs["irsb"]
        else:
            # Disable optimization; it doesn't work
            kwargs["opt_level"] = 0

            # Compute the block from the state.
            # Pray to the Powers that kwargs are compatible.
            irsb = state.block(extra_stop_points=exit_points, **kwargs).vex

        i = 0
        while i < len(irsb._ops):
            op = irsb._ops[i]
            if op.opcode == pypcode.OpCode.CALLOTHER:
                # This is a user-defined Pcode op.
                # Alter irsb to mimic its behavior, if we can.
                opnum = op.inputs[0].offset
                # Spoiler: we can't.
                raise EmulationError(f"Undefined user op {hex(opnum)}")

            else:
                i += 1

        # Force the engine to use our IR block
        kwargs["irsb"] = irsb

        # Turn the crank on the engine
        return super().successors(state, **kwargs)


class MSP430MachineDef(MSP430AbsMachineDef):
    arch = Architecture.MSP430
    pcode_language = "TI_MSP430:LE:16:default"


class MSP430XMachineDef(MSP430AbsMachineDef):
    arch = Architecture.MSP430X
    pcode_language = "TI_MSP430X:LE:32:default"
