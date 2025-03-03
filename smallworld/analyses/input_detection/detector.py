from angr.storage.memory_mixins.memory_mixin import MemoryMixin

from ...emulators.angr.exceptions import PathTerminationSignal
from ...emulators.angr.utils import reg_name_from_offset
from ...hinting import (
    UnderSpecifiedAddressHint,
    UnderSpecifiedMemoryHint,
    UnderSpecifiedRegisterHint,
    get_hinter,
)

hinter = get_hinter(__name__)


class InputDetectionMemoryMixin(MemoryMixin):
    # Configuration for when to halt for hints
    # I don't have control over the constructor for this class, so...
    halt_at_first_hint = False

    def _concretize_addr(self, supercall, addr, strategies=None, condition=None):
        res = supercall(addr, strategies=strategies, condition=condition)
        hint = UnderSpecifiedAddressHint(
            message="Dereferencing non-concrete address",
            instruction=self.state._ip.concrete_value,
            addr=str(addr),
            symbol="N/A",
        )
        hinter.info(hint)
        return res

    def concretize_read_addr(self, addr, strategies=None, condition=None):
        return self._concretize_addr(
            super().concretize_read_addr, addr, strategies, condition
        )

    def concretize_write_addr(self, addr, strategies=None, condition=None):
        return self._concretize_addr(
            super().concretize_write_addr, addr, strategies, condition
        )

    def _default_value(self, addr, size, **kwargs):
        res = super()._default_value(addr, size, **kwargs)
        if self.id == "reg":
            # We're dealing with registers
            reg_name = reg_name_from_offset(self.state.arch, addr, size)
            hint = UnderSpecifiedRegisterHint(
                message="Register used before initialization",
                register=reg_name,
                instruction=self.state._ip.concrete_value,
            )
        elif self.id == "mem":
            # We're dealing with memory
            hint = UnderSpecifiedMemoryHint(
                message="Memory used before initialization",
                address=addr,
                size=size,
                instruction=self.state._ip.concrete_value,
            )
        hinter.info(hint)
        if self.halt_at_first_hint:
            raise PathTerminationSignal()
        return res
