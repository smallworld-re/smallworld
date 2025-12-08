import typing

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
        if (
            self.base == "None"
            or self.index == "None"
            or self.scale == "None"
            or self.offset == "None"
        ):
            breakpoint()

    def address(self, emulator: emulators.Emulator) -> int:
        base = 0
        if self.base is not None:
            base = emulator.read_register(self.base)

        index = 0
        if self.index is not None:
            index = emulator.read_register(self.index)

        return base + self.scale * index + self.offset

    def to_json(self) -> dict:
        return {
            "base": self.base,
            "index": self.index,
            "scale": self.scale,
            "offset": self.offset,
        }

    def to_dict(self) -> dict:
        breakpoint()
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

        if "None" in string:
            breakpoint()

        return f"[{string}]"

    def __repr__(self) -> str:
        string = self.expr_string()
        return f"{self.__class__.__name__}({string})"
