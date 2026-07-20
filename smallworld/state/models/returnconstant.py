import logging
import typing

from ... import emulators, platforms, utils
from .cstd import ArgumentType, CStdCallingContext
from .model import Model

logger = logging.getLogger(__name__)


class ReturnConstant(Model):
    """A model that ignores its arguments and returns a fixed value.

    This is a "default" function model: rather than modeling the semantics
    of a particular library function, it simply consumes the call and
    returns a constant according to the ABI.  It's handy for stubbing out
    functions whose return value you want to pin (e.g. force ``fork`` to
    return 0) without writing a bespoke model.

    Unlike the named library-function models, this one is *parametric*, so
    it is constructed directly rather than obtained via :meth:`Model.lookup`::

        model = ReturnConstant(address, platform, abi, value=0)
        machine.add(model)

    Returning is an ABI-specific operation, but that logic is already
    abstracted by :class:`CStdCallingContext`.  Instead of defining a
    subclass per ABI, this model looks up the calling context for the
    requested platform/ABI and delegates to its ``set_return_value``.  As a
    result it works on every ABI the framework supports, for free.

    A ``return_type`` of :attr:`ArgumentType.VOID` produces a no-op model:
    the call is consumed and control returns to the caller, but no return
    register is written.

    Arguments:
        address: The instruction address which the model will hook.
        platform: The platform for which this model is defined.
        abi: The ABI according to which this model returns.
        value: The constant to return.  Must be an ``int`` for integral or
            pointer return types, or a ``float`` for ``FLOAT``/``DOUBLE``.
            Ignored when ``return_type`` is ``VOID``.
        return_type: The C type of the return value.  Determines which
            register(s) are written and how ``value`` is encoded.  Defaults
            to :attr:`ArgumentType.POINTER` (register-width, no truncation).
    """

    # These override the abstract properties on Model with concrete class
    # attributes so ReturnConstant is directly instantiable.  They are
    # replaced with the real values per-instance in __init__.
    name = "return-constant"
    platform = None  # type: ignore[assignment]
    abi = None  # type: ignore[assignment]

    def __init__(
        self,
        address: int,
        platform: platforms.Platform,
        abi: platforms.ABI,
        value: typing.Union[int, float] = 0,
        return_type: ArgumentType = ArgumentType.POINTER,
    ):
        # platform/abi must be set before Model.__init__, which builds
        # self.platdef from self.platform.
        self.platform = platform
        self.abi = abi
        self.value = value

        # Borrow the ABI-specific return machinery.  We match on platform AND
        # abi (CStdCallingContext.for_platform ignores the abi), and exclude
        # Model subclasses so we resolve the pure calling-context base (e.g.
        # AMD64SysVCallingContext) rather than a concrete function model that
        # happens to share the platform.
        try:
            self._context: CStdCallingContext = utils.find_subclass(
                CStdCallingContext,
                lambda x: x.platform == platform
                and x.abi == abi
                and not issubclass(x, Model),
            )
        except ValueError:
            raise ValueError(f"no calling context for {platform} with ABI '{abi}'")
        self._context.return_type = return_type

        super().__init__(address)

    def model(self, emulator: emulators.Emulator) -> None:
        super().model(emulator)

        if self._context.return_type == ArgumentType.VOID:
            # No-op: consume the call and return without writing a value.
            logger.debug("return-constant modeling void return")
            return

        logger.debug(f"return-constant returning {self.value!r}")
        self._context.set_return_value(emulator, self.value)


__all__ = ["ReturnConstant"]
