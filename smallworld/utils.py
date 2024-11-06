from __future__ import annotations

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
    """A class representing a collection of non-overlapping ranges."""

    def __init__(self):
        self.ranges = []

    def is_empty(self):
        """Returns true iff there are no ranges in this collection."""
        return 0 == len(self.ranges)

    def find_range(self, value: int) -> typing.Optional[int]:
        """Returns a single range containing this value, or None if no range contains it."""

        for i, (start, end) in enumerate(self.ranges):
            if start <= value < end:
                return i
        return None

    def contains(self, arange: typing.Tuple[int, int]) -> bool:  # new function
        """Returns True iff this range `arange` overlaps with one or more ranges in the collection."""
        self._check_range(arange)
        start, end = arange
        start_index, start_found = self._find_closest_range(start)
        end_index, end_found = self._find_closest_range(end - 1)

        if start_index == end_index and not start_found and not end_found:
            return False
        else:
            return True

    def update(self, other: RangeCollection) -> None:
        """Add all ranges in this collection to this other collection."""
        for rng in other.ranges:
            self.add_range(rng)

    def add_value(self, value: int) -> None:
        """Add a single value to this collection."""
        self.add_range((value, value + 1))

    def get_missing_ranges(
        self, arange: typing.Tuple[int, int]
    ) -> typing.List[typing.Tuple[int, int]]:
        """Return list of ranges missing in this collection.

        Say min_r is the *first* range in the collection, i.e., the one with the lowest start value.
        And say that max_r is the *last* range in the collection, i.e., the one wiht the largest end value.

        Then this method will return the list of ranges that, if added
        to this collection, would turn it into a single range, starting with
        min_r.start, and ending with max_r.end.
        """

        new_start, new_end = arange
        missing_ranges = []
        self._check_range(arange)

        if not len(self.ranges):
            return [arange]

        for start, end in self.ranges:
            # our range is completely before the first range
            if new_end < start:
                missing_ranges.append((new_start, new_end))
                return missing_ranges

            # New range starts after this range ends
            elif new_start > end:
                continue

            # We have found our start i.e. new_start >= prev end

            # Gap before current start, it falls overlapping ranges
            if new_start < start:
                missing_ranges.append((new_start, min(new_end, start)))

            # Adjust new start to end of current range
            new_start = max(new_start, end)

            # If the new range ends before the current range, done
            if new_start >= new_end:
                break

        if new_start < new_end:
            missing_ranges.append((new_start, new_end))

        return missing_ranges

    # Returns either the range or the range BEFORE you
    # -1 if its lower than first range
    def _find_closest_range(self, value: int) -> typing.Tuple[int, bool]:
        """Attempt to find this value in some range in the collection and report result.

        Result return value is the pair (index, found), where
        `index` is list index of the closest range to the left of
           this value
        `found` is a boolean indicating if this value is actually
        in the range at `index`.

        Return -1 if this value is strictly *before* every range in the collection.

        """

        for i, (start, end) in enumerate(self.ranges):
            if start <= value < end:
                return i, True
            elif value < start:
                return i - 1, False
        return 0, False

    def find_closest_range(
        self, value: int
    ) -> typing.Tuple[typing.Optional[typing.Tuple[int, int]], bool]:
        """Attempt to find this value in some range in the collection and report result.

        Result return value is the pair (range, found), where
        `range` is closest range to the left of this value
        `found` is a boolean indicating if this value is actually
        in the range.

        Return None for `range` if this value is strictly *before* every range in the collection.

        """
        (index, found) = self._find_closest_range(value)
        arange = None
        if arange != -1:
            arange = self.ranges[index]
        return (arange, found)

    def remove_range(self, arange: typing.Tuple[int, int]) -> None:
        """Remove this range from the collection.

        Note that this doesn't look for this specific range and remove
        it. Rather, it compares this range to every range in the collection
        and, for each, removes the intersection with the input `arange`.

        """

        start, end = arange
        self._check_range(arange)

        i1, _ = self._find_closest_range(start)
        range1 = self.ranges[i1]
        i2, _ = self._find_closest_range(end)
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

    def _check_range(self, arange: typing.Tuple[int, int]) -> None:
        start, end = arange
        if start > end or start == end:
            raise ValueError(f"Start value must be less than end in {arange}")

    def add_range(self, arange: typing.Tuple[int, int]) -> None:
        """Add this range to the collection."""

        self._check_range(arange)
        start, end = arange

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

        return
