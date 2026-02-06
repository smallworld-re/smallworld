import typing

import claripy

from .. import emulators
from .instructions import MemoryReferenceOperand


class BSIDMemoryReferenceOperand(MemoryReferenceOperand):
    """Memory Operand based on the base-scale-index-displacement pattern."""

    def __init__(
        self,
        base: typing.Optional[str] = None,
        index: typing.Optional[str] = None,
        scale: int = 1,
        offset: int = 0,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        self.base = base
        self.index = index
        self.scale = scale
        self.offset = offset

    def address(self, emulator: emulators.Emulator) -> int:
        base = 0
        if self.base is not None:
            base = emulator.read_register(self.base)

        index = 0
        if self.index is not None:
            index = emulator.read_register(self.index)

        return base + self.scale * index + self.offset

    def symbolic_address(self, emulator: emulators.Emulator) -> claripy.ast.bv.BV:
        platdef = emulator.platdef  # type: ignore

        zero = claripy.BVV(0, platdef.address_size * 8)
        base = zero
        if self.base is not None:
            base = emulator.read_register_symbolic(self.base)

        index = zero
        if self.index is not None:
            index = emulator.read_register_symbolic(self.index)

        scale = claripy.BVV(self.scale, platdef.address_size * 8)
        offset = claripy.BVV(self.offset, platdef.address_size * 8)
        return base + scale * index + offset

    def to_json(self) -> dict:
        return {
            "base": self.base,
            "index": self.index,
            "scale": self.scale,
            "offset": self.offset,
        }

    def to_dict(self) -> dict:
        return self.to_json()

    @classmethod
    def from_json(cls, dict):
        if any(k not in dict for k in ("base", "index", "scale", "offset")):
            raise ValueError(f"malformed {cls.__name__}: {dict!r}")

        return cls(**dict)

    def expr_string(self) -> str:
        string = ""

        # not sure why these things are strings sometimes but they are
        def nn(x):
            if x is not None and x != "None":
                return True
            return False

        if self.base is not None and self.base != "None":
            string = self.base
        if nn(self.index):
            if nn(self.scale):
                string = f"{string}+{self.scale}*{self.index}"
            else:
                string = f"{string}+{self.index}"
        if self.offset < 0:
            string = f"{string}{self.offset:x}"
        elif self.offset > 0:
            string = f"{string}+{self.offset:x}"

        return f"[{string}]"

    def __repr__(self) -> str:
        string = self.expr_string()
        return f"{self.__class__.__name__}({string})"


class x86BSIDMemoryReferenceOperand(BSIDMemoryReferenceOperand):
    def address(self, emulator: emulators.Emulator) -> int:
        a = super().address(emulator)
        if self.base == "rip" or self.base == "eip":
            # for x86, if address is computed wrt the instruction
            # pointer (rip or eip) the value used for that should be
            # start of *next* instruction.
            # However, unicorn always reports start of current instruction as value in rip/eip.
            # This is a grotty fixup.
            if type(emulator) is emulators.UnicornEmulator:
                a += emulator.current_instruction().size  # type: ignore
        return a
