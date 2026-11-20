"""The C99 models for SDCC's reentrant 8051 convention.

The library is the same in both conventions; only where arguments go
differs.  So each model here is generated from its counterpart in
:mod:`smallworld.state.models.mcs51.sdcc.c99`, with
:class:`MCS51SDCCStackAutoModel` supplying the convention:
``MCS51SDCCStackAutoMemset`` from ``MCS51SDCCMemset``, and so on.  A model
added there is added here too.
"""

import typing

from ...sdcc import c99 as _sdcc_c99
from ..sdccstackauto import MCS51SDCCStackAutoModel


def _stack_auto(model: type) -> type:
    # MCS51SDCCStackAutoModel subclasses MCS51SDCCModel, so it comes before
    # it in the result's MRO and its calling convention wins.
    name = model.__name__.replace("MCS51SDCC", "MCS51SDCCStackAuto", 1)
    return type(model)(
        name,
        (model, MCS51SDCCStackAutoModel),
        {"__module__": __name__, "__qualname__": name, "__doc__": model.__doc__},
    )


_names: typing.List[str] = getattr(_sdcc_c99, "__all__")
_models = [_stack_auto(getattr(_sdcc_c99, name)) for name in _names]
globals().update((model.__name__, model) for model in _models)
__all__: typing.List[str] = [model.__name__ for model in _models]
