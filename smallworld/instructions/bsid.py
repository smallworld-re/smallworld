import functools
import typing

import claripy

from .. import emulators
from ..exceptions import UnsupportedRegisterError
from ..platforms import Platform, PlatformDef
from .instructions import MemoryReferenceOperand, _log_fallback_once


@functools.lru_cache(maxsize=None)
def _platform_def(
    platform: typing.Optional[Platform],
) -> typing.Optional[PlatformDef]:
    """`PlatformDef.for_platform`, cached and None-tolerant.

    Only reached for an emulator that carries no `platdef` of its own;
    `for_platform` walks every subclass uncached, so the result is memoized
    per platform rather than resolved per operand.
    """
    if platform is None:
        return None
    try:
        return PlatformDef.for_platform(platform)
    except ValueError:
        return None


class BSIDMemoryReferenceOperand(MemoryReferenceOperand):
    """Memory Operand based on the base-scale-index-displacement pattern."""

    def __init__(
        self,
        segment: typing.Optional[str] = None,
        base: typing.Optional[str] = None,
        index: typing.Optional[str] = None,
        scale: int = 1,
        offset: int = 0,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)

        self.segment = segment
        self.base = base
        self.index = index
        self.scale = scale
        self.offset = offset

    def _segment_base_register(
        self, emulator: emulators.Emulator
    ) -> typing.Optional[str]:
        """The register holding this operand's segment base, or None when the
        operand names no segment or the platform models no base for it.

        `segment` used to be carried but never read, so `fs:[0x28]` resolved to
        0x28 -- the segment base silently missing from every address computed
        from a Capstone-produced operand. i386 legitimately has no such
        register (it models only the 2-byte selectors), so that case falls back
        to omitting the base rather than raising.

        `platdef` is not on the Emulator interface -- PandaEmulator keeps one
        only on its worker thread and StyxEmulator has none -- so fall back to
        resolving it from `platform`, which is. Probing for it and giving up
        would silently reinstate the bug on exactly those backends.
        """
        if not self.segment:
            return None
        platdef = getattr(emulator, "platdef", None)
        if platdef is None:
            platdef = _platform_def(getattr(emulator, "platform", None))
        if platdef is None:
            return None
        return platdef.segment_base_registers.get(self.segment)

    def _no_segment_base(self, emulator: emulators.Emulator, name: str) -> None:
        """Report that this emulator cannot supply a segment base.

        Triton deliberately omits fsbase/gsbase from its register map, and the
        Ghidra and Panda machine defs map them to None, so reading one raises.
        Raising here would turn an address that used to compute into a crash,
        so the callers below degrade -- but the answer is then wrong by exactly
        the segment base, which is worth a warning rather than the per-access
        debug line it started as. Keyed on the emulator and register, never on
        the operand, so the once-guard stays bounded.
        """
        _log_fallback_once(
            f"{type(emulator).__name__} cannot read {name!r}; segment-relative "
            f"addresses will resolve without their segment base"
        )

    def _segment_base(self, emulator: emulators.Emulator) -> typing.Optional[int]:
        """This operand's segment base value, or None to contribute nothing."""
        name = self._segment_base_register(emulator)
        if name is None:
            return None
        try:
            return emulator.read_register(name)
        except (UnsupportedRegisterError, NotImplementedError):
            self._no_segment_base(emulator, name)
            return None

    def _segment_base_symbolic(
        self, emulator: emulators.Emulator
    ) -> typing.Optional[claripy.ast.bv.BV]:
        """`_segment_base` for the symbolic path.

        Two methods rather than one with a `symbolic` flag: the flag makes the
        return `int | BV | None`, which is unannotatable, and an unannotated
        return is an implicit `Any` that hides a BV leaking into `address`'s
        declared `int`. NotImplementedError is caught alongside the
        unsupported-register case because that is what the base Emulator
        raises for a backend with no symbolic support at all -- before this
        operand grew a segment base, `fs:[0x28]` read no registers and so
        could not raise there.
        """
        name = self._segment_base_register(emulator)
        if name is None:
            return None
        try:
            return emulator.read_register_symbolic(name)
        except (UnsupportedRegisterError, NotImplementedError):
            self._no_segment_base(emulator, name)
            return None

    def address(self, emulator: emulators.Emulator) -> int:
        base = 0
        if self.base is not None:
            base = emulator.read_register(self.base)

        segment_base = self._segment_base(emulator)
        if segment_base is not None:
            base += segment_base

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

        segment_base = self._segment_base_symbolic(emulator)
        if segment_base is not None:
            base = base + segment_base

        index = zero
        if self.index is not None:
            index = emulator.read_register_symbolic(self.index)

        scale = claripy.BVV(self.scale, platdef.address_size * 8)
        offset = claripy.BVV(self.offset, platdef.address_size * 8)
        return base + scale * index + offset

    def to_json(self) -> dict:
        return {
            # Dropped here until `segment` started contributing the segment
            # base to address(): a round-trip through JSON would now silently
            # move `fs:[0x28]` from fsbase+0x28 back to 0x28 -- the same class
            # of bug as the `size` note below.
            "segment": self.segment,
            "base": self.base,
            "index": self.index,
            "scale": self.scale,
            "offset": self.offset,
            # `size` participates in MemoryReferenceOperand equality and
            # hashing, so dropping it here made a round-trip silently rewrite
            # the operand's identity for every width but the default 4 -- and
            # concretize() then read the wrong number of bytes.
            "size": self.size,
        }

    def to_dict(self) -> dict:
        return self.to_json()

    @classmethod
    def from_json(cls, dict):
        if any(k not in dict for k in ("base", "index", "scale", "offset")):
            raise ValueError(f"malformed {cls.__name__}: {dict!r}")

        # `size` and `segment` are optional so payloads written before to_json
        # emitted them still load; they fall back to the __init__ defaults.
        return cls(**dict)

    def expr_string(self) -> str:
        string = ""

        # not sure why these things are strings sometimes but they are
        def nn(x):
            if x is not None and x != "None":
                return True
            return False

        if self.segment:
            string = self.segment + ":("

        if self.base is not None and self.base != "None":
            string = string + self.base
        if nn(self.index):
            if nn(self.scale):
                string = f"{string}+{self.scale}*{self.index}"
            else:
                string = f"{string}+{self.index}"
        if self.offset < 0:
            string = f"{string}{self.offset:x}"
        elif self.offset > 0:
            string = f"{string}+{self.offset:x}"

        if self.segment:
            string = string + ")"

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
