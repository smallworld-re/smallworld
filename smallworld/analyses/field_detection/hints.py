import dataclasses
import typing

from ... import hinting


class ClaripySerializable(hinting.Serializable):
    """Serializable wrapper that allows serializing claripy expressions in hints."""

    @classmethod
    def claripy_to_dict(cls, expr):
        if (
            expr is None
            or isinstance(expr, int)
            or isinstance(expr, str)
            or isinstance(expr, bool)
        ):
            return expr
        else:
            return {"op": expr.op, "args": list(map(cls.claripy_to_dict, expr.args))}

    def __init__(self, expr):
        self.expr = expr

    def to_dict(self):
        return self.claripy_to_dict(self.expr)

    @classmethod
    def from_dict(cls, dict):
        raise NotImplementedError(
            "Rebuilding clairpy is a lot harder than tearing it apart"
        )


@dataclasses.dataclass(frozen=True)
class FieldHint(hinting.Hint):
    address: int = 0
    size: int = 0

    def pp(self, out):
        out(self.message)
        out(f"  address:    {hex(self.address)}")
        out(f"  size:       {self.size}")


@dataclasses.dataclass(frozen=True)
class TrackedFieldHint(FieldHint):
    label: str = ""

    def pp(self, out):
        super().pp(out)
        out(f"  label:      {self.label}")


@dataclasses.dataclass(frozen=True)
class FieldEventHint(FieldHint):
    """Hint representing a detected, unhandled field"""

    pc: int = 0
    guards: typing.List[typing.Tuple[int, ClaripySerializable]] = dataclasses.field(
        default_factory=list
    )
    access: str = ""

    def pp(self, out):
        super().pp(out)
        out(f"  pc:         {hex(self.pc)}")
        out(f"  access:     {self.access}")
        out("  guards:")
        for pc, guard in self.guards:
            out(
                f"    {hex(pc)}: {guard.expr.shallow_repr()} [{list(filter(lambda x: x.op != 'BVV', guard.expr.leaf_asts()))}]"
            )


@dataclasses.dataclass(frozen=True)
class UnknownFieldHint(FieldEventHint):
    """Hint representing an access of an unknown field.

    The expression loaded from memory is not
    a simple slice of any known label.
    """

    message: str = "Accessed unknown field"  # Don't need to replace
    expr: str = ""

    def pp(self, out):
        super().pp(out)
        out(f"  expr:       {self.expr}")


@dataclasses.dataclass(frozen=True)
class PartialByteFieldAccessHint(FieldEventHint):
    """Hint representing an access to part of a known field."""

    message: str = "Partial access to known field"  # Don't need to replace
    label: str = ""
    start: int = 0
    end: int = 0

    def pp(self, out):
        super().pp(out)
        out(f"  field:      {self.label}[{self.start}:{self.end}]")


@dataclasses.dataclass(frozen=True)
class PartialByteFieldWriteHint(PartialByteFieldAccessHint):
    """Hint representing a write to part of a known field.

    Also includes the data I'm trying to write
    """

    message: str = "Partial write to known field"  # Don't need to replace
    access: str = "write"  # Don't need to replace
    expr: str = ""

    def pp(self, out):
        super().pp(out)
        out(f"  expr:       {self.expr}")


@dataclasses.dataclass(frozen=True)
class PartialBitFieldAccessHint(FieldEventHint):
    """Hint representing an access to a bit field within a known field."""

    message: str = "Bit field access in known field"  # Don't need to replace
    label: str = ""
    start: int = 0
    end: int = 0

    def pp(self, out):
        super().pp(out)
        out(f"  field:      {self.label}[{self.start}:{self.end}]")
