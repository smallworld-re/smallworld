from .... import emulators
from ....platforms.defs.sparc import SPARC_RETURN_ADDRESS_OFFSET
from ..model import Model


class SPARC32Model(Model):
    """Base class for models on 32-bit SPARC.

    `call` leaves its own address in %o7, and the matching return goes past
    the call and its delay slot, to %o7 + 8. A model runs in its caller's
    register window -- it never executes `save` -- so %o7 is still the
    caller's when the model returns.

    The generic `Model` does not know this rule, so a SPARC32 model must
    derive from this class (the System V C models do).
    """

    def get_return_address(self, emulator: emulators.Emulator, pop=False) -> int:
        return (emulator.read_register("o7") + SPARC_RETURN_ADDRESS_OFFSET) & 0xFFFFFFFF


__all__ = ["SPARC32Model"]
