import abc
import bisect
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


class RangeCollection:
    def __init__(self):
        self.ranges = []

    def is_empty(self):
        return 0 == len(self.ranges)

    def find_range(self, value: int) -> typing.Optional[int]:
        for i, (start, end) in enumerate(self.ranges):
            if start <= value < end:
                return i
        return None

    def add_value(self, value: int) -> None:
        self.add_range((value, value + 1))

    def get_missing_ranges(
        self, arange: typing.Tuple[int, int]
    ) -> typing.List[typing.Tuple[int, int]]:
        new_start, new_end = arange
        missing_ranges = []

        if not len(self.ranges):
            return [arange]

        for start, end in self.ranges:
            # We were at the last part
            if new_end < start:
                missing_ranges.append((new_start, new_end))

            # Haven't found our start yet
            elif new_start > end:
                continue

            # We have found our start i.e. new_start > prev end

            # Gap before current start
            if new_start < start:
                missing_ranges.append((new_start, min(new_end, start)))

            new_start = max(new_start, end)

            if new_start > new_end:
                break

        return missing_ranges

    # Returns either the range or the range BEFORE you
    def find_closest_range(self, value : int) -> int:
        for i, (start, end) in enumerate(self.ranges):
            if start <= value < end:
                return i
            elif value < start:
                return i
        return 0

    def remove_range(self, arange : typing.Tuple[int, int]) -> None:
        start, end = arange
        if start > end or start == end:
            print("no")
            return

        i1 = self.find_closest_range(start)
        range1 = self.ranges[i1]
        i2 = self.find_closest_range(end)
        range2 = self.ranges[i2]

        # Keep everything up to our first find
        new_ranges = self.ranges[:i1]

        # If we fall in our range, change it
        # If we fall outside, then we dont need it
        if range1[0] <= start < range1[1]:
            new_ranges.append((range1[0], start))

        # If we fall in our range, change it
        # If we fall outside of it we need to add it
        if range2[0] <= end < range2[1]:
            new_ranges.append((end, range2[1]))
        else:
            new_ranges.append(range2)

        if i2 + 1 < len(self.ranges):
            new_ranges.extend(self.ranges[i2 + 1 :])

        self.ranges = new_ranges
        return

    def add_range(self, arange : typing.Tuple[int,int]) -> None:
        start, end = arange
        if start > end or start == end:
            print("no")
            return

        i = bisect.bisect_left(self.ranges, arange)
        new_ranges = []

        # Handle the case where the range falls directly to the left of the idx
        if i > 0 and start <= self.ranges[i - 1][1]:
            i -= 1
            start = min(start, self.ranges[i][0])
            end = max(end, self.ranges[i][1])

        # Now make the new range be everything up until where things changed
        new_ranges.extend(self.ranges[:i])

        # Now merge will all right bounds until we are the min right bound
        while i < len(self.ranges) and self.ranges[i][0] <= end:
            start = min(start, self.ranges[i][0])
            end = max(end, self.ranges[i][1])
            i += 1

        # Add the merged bound
        new_ranges.append((start, end))

        # Add the remaining non-overlapping bounds
        new_ranges.extend(self.ranges[i:])

        self.ranges = new_ranges

        return new_ranges
