import abc
import inspect
import typing


class MetadataMixin(metaclass=abc.ABCMeta):
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The name of this analysis.

        Names should be kebab-case, all lowercase, no whitespace for proper
        formatting.
        """
        pass

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """A description of this analysis.

        Descriptions should be a single sentence, lowercase, with no final
        punctuation for proper formatting.
        """

        return ""

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """The version string for this analysis.

        We recommend using `Semantic Versioning`_

        .. _Semantic Versioning:
            https://semver.org/
        """

        return ""


def find_subclass(
    cls: typing.Type[typing.Any],
    check: typing.Callable[[typing.Type[typing.Any]], bool],
    *args,
    **kwargs,
):
    """Find and instantiate a subclass for dependency injection

    This pattern involves finding an implementation by sematic criteria,
    rather than explicity encoding a reference to it.

    This makes for nice modular code, since the invoker
    doesn't need to get updated every time a new module is added.

    Arguments:
        cls: The class representing the interface to search
        check: Callable for testing the desired criteria
        args: Any positional/variadic args to pass to the initializer
        kwargs: Any keyword arguments to pass to the initializer

    Returns: An instance of a subclass of cls matching the criteria from check

    Raises:
        ValueError: If no subclass of cls matches the criteria
    """
    class_stack: typing.List[typing.Type[typing.Any]] = [cls]
    while len(class_stack) > 0:
        impl: typing.Type[typing.Any] = class_stack.pop(-1)

        if not inspect.isabstract(impl) and check(impl):
            return impl(*args, **kwargs)
        # __subclasses__ is not transitive;
        # need to call this on each sublclass to do a full traversal.
        class_stack.extend(impl.__subclasses__())

    raise ValueError(f"No instance of {cls} matching criteria")
