import typing

from .state import Register


class X86MMRRegister(Register):
    """x86 Memory Management Register

    These things have a special internal format,
    represented by the 4-tuple (selector, base, limit, flags).

    Unicorn takes these as a 4-tuple.

    angr doesn't take an actual value;
    it takes a pointer to a host-allocated table.  I think.
    """

    def set_content(self, content: typing.Optional[typing.Any]):
        self._content = content

    def __str__(self):
        s = f"Reg({self.name},{self.size})="
        x = self.get_content()
        if x is None:
            s = s + "=None"
        elif isinstance(x, tuple):
            s = s + ", ".join(map(lambda v: hex(v), x))
        else:
            s = s + "External ref {hex(x)}"
        return s
