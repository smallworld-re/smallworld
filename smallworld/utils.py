from __future__ import annotations

import abc
import inspect
import io
import typing
from collections.abc import Iterable


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


class RBNode:
    def __init__(self, key, value, nil):
        self.key = key
        self.value = value
        self.is_black = False
        self.parent = None
        self.child = [nil, nil]


class RBTree(Iterable):
    """A self-balancing binary search tree

    This implements a canonical red-black tree.
    Values can be whatever you want, as long as all items
    in the tree can use the same key function.

    You can mutate values outside the tree,
    as long as you don't change their keys.

    Arguments:
        key: Function for converting values into integers for comparison
    """

    def __init__(self, key: typing.Callable[[typing.Any], int] = lambda x: x):
        self._key = key
        self._nil: RBNode = RBNode(0, None, None)
        self._nil.is_black = True
        self._root: RBNode = self._nil

    def _rotate(self, P, branch):
        G = P.parent
        S = P.child[1 - branch]

        if S is self._nil:
            raise ValueError("Can't rotate; S is nil!")

        C = S.child[branch]

        P.child[1 - branch] = C
        if C is not self._nil:
            C.parent = P

        S.child[branch] = P
        P.parent = S

        S.parent = G

        if G is not None:
            branch = 1 if P is G.child[1] else 0
            G.child[branch] = S
        else:
            self._root = S

        return S

    def insert(self, value: typing.Any) -> None:
        """Insert a value into the tree

        Arguments:
            value: The value to insert

        Raises:
            ValueError: If there's a key collision between value and something in the tree
        """
        N = RBNode(self._key(value), value, self._nil)

        # Case 0: This is the first node ever
        if self._root is self._nil:
            self._root = N
            return

        # Insert into tree normally
        P = self._root
        while True:
            if P.key > N.key:
                branch = 0
            elif P.key < N.key:
                branch = 1
            else:
                raise ValueError(f"Key collision on {value}")
            if P.child[branch] is self._nil:
                break
            P = P.child[branch]
        N.parent = P
        P.child[branch] = N

        # Rebalance the tree iteratively
        while P is not None:
            if P.is_black:
                # Case 1: P is black; we're all fine.
                break

            G = P.parent
            if G is None:
                # Case 4: P is the root and red
                # Since N is red, make P black
                P.is_black = True
                break

            # Find our uncle
            branch = 0 if G.child[0] is P else 1
            U = G.child[1 - branch]

            if U.is_black:
                if N is P.child[1 - branch]:
                    # Case 5: P is red, U is black, and N is an inner grandchild of G.
                    # Rotate the tree so it's an outer grandchild
                    self._rotate(P, branch)
                    N = P
                    P = G.child[branch]
                # Case 6: P is red, U is black, N is an outer grandchild of G
                # Rotate the tree to fix things
                self._rotate(G, 1 - branch)
                P.is_black = True
                G.is_black = False
                break

            # Case 2: P and U are red
            # Make P and U black, and G red
            P.is_black = True
            U.is_black = True
            G.is_black = False

            # Iterate one black level (2 tree levels) higher.
            N = G
            P = N.parent

        # Case 3: N is now the root and red
        # self._verify_rb(self._root)
        return

    def _get_node(self, value):
        # Helper for fetching a node,
        # or raising an error if we can't find it.
        k = self._key(value)
        N = self._root
        while N is not self._nil:
            if k == N.key:
                if value == N.value:
                    return N
                else:
                    raise ValueError(f"Key {k} had unexpected value {N.value}")
                break
            elif k < N.key:
                N = N.child[0]
            elif N.key < k:
                N = N.child[1]
        raise ValueError(f"Value {value} is not in the tree")

    def _verify_rb(self, N, c=0):
        # Verify the following properties:
        #
        # - Doubly-Linked Tree:
        #   - N.parent is None iff self._root is N
        #   - N in N.parent.child
        #
        # - Binary Search Tree:
        #   - N.child[0].key < N.key < N.child[1].key
        #
        # - Red-Black Tree:
        #   - Red nodes cannot have red children
        #   - All paths between root and nil contain the same number of black nodes
        if N is self._nil:
            return c + 1
        if N.parent is None and N is not self._root:
            raise Exception(f"DLT violation at {hex(N.key)}: Non-root has empty parent")
        if N is self._root and N.parent is not None:
            raise Exception(f"DLT violation at {hex(N.key)}: Root has non-empty parent")
        L = N.child[0]
        R = N.child[1]
        if L is not self._nil:
            if N.key <= L.key:
                raise Exception(f"BST violation at {hex(N.key)}: Left is {hex(L.key)}")
            if L.parent is not N:
                raise Exception(
                    f"DLT violation at {hex(N.key)}: Left child {hex(L.key)} parent broken"
                )
            if not N.is_black and not L.is_black:
                raise Exception(
                    f"RBT violation at {hex(N.key)}: N and left child {hex(L.key)} are red"
                )
        if R is not self._nil:
            if N.key >= R.key:
                raise Exception(f"BST violation at {hex(N.key)}: Right is {hex(R.key)}")
            if R.parent is not N:
                raise Exception(
                    f"DLT violation at {hex(N.key)}: Left child {R.key} parent broken"
                )
            if not N.is_black and not R.is_black:
                raise Exception(
                    f"RBT violation at {hex(N.key)}: N and right child {hex(R.key)} are red"
                )
        c += 1 if N.is_black else 0
        left_c = self._verify_rb(L, c)
        right_c = self._verify_rb(R, c)
        if left_c != right_c:
            raise Exception(f"RBT violation at {hex(N.key)}: {left_c} vs {right_c}")
        return left_c

    def _remove_node(self, N):
        if N.child[0] is not self._nil and N.child[1] is not self._nil:
            # Case 1: N has 2 children
            # Find in-order successor
            S = N.child[1]
            while S.child[0] is not self._nil:
                S = S.child[0]
            # Swap values
            k = N.key
            v = N.value
            N.key = S.key
            N.value = S.value
            S.key = k
            S.value = v
            # Remove the successor
            self._remove_node(S)

        elif N.child[0] is not self._nil or N.child[1] is not self._nil:
            # Case 2: N has 1 child
            C = N.child[0] if N.child[0] is not self._nil else N.child[1]
            # Make C black
            C.is_black = True

            if N.parent is None:
                # Case 2a: N is the root; no parent
                # C is now the root.
                self._root = C
                C.parent = None
            else:
                # Case 2b: N is not the root; parent
                P = N.parent
                branch = 0 if N is P.child[0] else 1
                # Prune N from the tree
                C.parent = P
                P.child[branch] = C

        elif N.parent is None:
            # Case 3: N has no children and N is the root
            # Make the root nil; we're empty
            self._root = self._nil

        elif not N.is_black:
            # Case 4: N has no children and N is red
            # Prune N out of the tree
            P = N.parent
            branch = 0 if P.child[0] is N else 1
            P.child[branch] = self._nil

        else:
            # Case 5: N has no children and N is black
            # Can't just delete the node; need to rebalance
            P = N.parent
            branch = 0 if P.child[0] is N else 1
            P.child[branch] = self._nil

            while P is not None:
                # Find our sibling, distant nephew, and close nephew
                S = P.child[1 - branch]
                D = S.child[1 - branch]
                C = S.child[branch]

                if not S.is_black:
                    # Case 5.3: S is red; P, C, D must be black
                    self._rotate(P, branch)

                    P.is_black = False
                    S.is_black = True

                    S = C
                    D = S.child[1 - branch]
                    C = S.child[branch]
                    # S is now black; handle according to 5.4, 5.5 or 5.6

                if D is not self._nil and not D.is_black:
                    # Case 5.6: S is black, D is red
                    self._rotate(P, branch)
                    S.is_black = P.is_black
                    P.is_black = True
                    D.is_black = True
                    break

                if C is not self._nil and not C.is_black:
                    # Case 5.5: S is black, C is red
                    self._rotate(S, 1 - branch)
                    S.is_black = False
                    C.is_black = True
                    D = S
                    S = C

                    # Now S is red and D is black
                    # We match case 5.6
                    self._rotate(P, branch)
                    S.is_black = P.is_black
                    P.is_black = True
                    D.is_black = True
                    break

                if not P.is_black:
                    # Case 5.4: P is red, S, C, and D are black
                    # Correct colors and we're done
                    S.is_black = False
                    P.is_black = True
                    break

                S.is_black = False
                N = P
                P = N.parent
                branch = 0 if P is None or P.child[0] is N else 1

            # Case 5.1: N is the new root; we're done.
        # self._verify_rb(self._root, 0)
        return

    def remove(self, value: typing.Any) -> None:
        """Remove a value from the tree

        Arguments:
            value: The value to remove

        Raises:
            ValueError: If `value` is not in the tree
        """
        N = self._get_node(value)
        self._remove_node(N)

    def extend(self, iterable: Iterable) -> None:
        """Add all values from an iterable to this tree

        Arguments:
            iterable: Iterable containing the values you want to add
        """
        for x in iterable:
            self.insert(x)

    def is_empty(self) -> bool:
        """Check if the tree is empty

        Returns:
            True if the tree is empty, else false.
        """
        return self._root is self._nil

    def contains(self, value: typing.Any) -> bool:
        """Check if the tree contains a value

        Arguments:
            value: The value to locate

        Returns:
            True if `value` is in the tree, else False
        """
        try:
            self._get_node(value)
            return True
        except:
            return False

    def bisect_left(self, value: typing.Any) -> typing.Optional[typing.Any]:
        """Find the value or its in-order predecessor

        Arguments:
            value: The value to search for
        Returns:
            - `value` if `value` is in the tree
            - The value with the highest key less than that of `value`
            - `None`, if there are no values with a key less than that of `value`
        """
        k = self._key(value)
        N = self._root
        # Traverse the tree to find our match
        while N is not self._nil:
            if k == N.key:
                return N.value
            elif k < N.key:
                if N.child[0] is self._nil:
                    break
                N = N.child[0]
            elif N.key < k:
                if N.child[1] is self._nil:
                    break
                N = N.child[1]

        if k < N.key:
            # Our match is to our right.
            # We need its in-order predecessor
            # This is the first ancestor for which our subtree is greater
            P = N.parent
            while P is not None:
                branch = 0 if N is P.child[0] else 1
                N = P
                P = N.parent
                if branch == 1:
                    break
            if k < N.key:
                # We are already the left-most value
                return None

        return N.value

    def bisect_right(self, value: typing.Any) -> typing.Optional[typing.Any]:
        """Find the value or its in-order successor

        Arguments:
            value: The value to search for
        Returns:
            - `value` if `value` is in the tree
            - The value with the lowest key greater than that of `value`
            - `None`, if there are no values with a key greater than that of `value`
        """
        k = self._key(value)
        N = self._root
        # Traverse the tree to find our match
        while N is not self._nil:
            if k == N.key:
                return N.value
            elif k < N.key:
                if N.child[0] is self._nil:
                    break
                N = N.child[0]
            elif k > N.key:
                if N.child[1] is self._nil:
                    break
                N = N.child[1]

        if k > N.key:
            # Our match is to our left.
            # We need its in-order successor
            # This is the first ancestor for which our subtree is less
            P = N.parent
            while P is not None:
                branch = 0 if N is P.child[0] else 1
                N = P
                P = N.parent
                if branch == 0:
                    break
            if k > N.key:
                # We are already the right-most value
                return None
        return N.value

    def _values(self, N):
        if N is not self._nil:
            for v in self._values(N.child[0]):
                yield v
            yield N.value
            for v in self._values(N.child[1]):
                yield v

    def values(self) -> typing.Any:
        """Generate values in the tree in in-order order

        Yields:
            Each value in the tree in in-order order
        """
        for v in self._values(self._root):
            yield v

    def __iter__(self):
        return iter(self.values())


class RangeCollection(Iterable):
    """A collection of non-overlapping ranges"""

    def __init__(self):
        # Back with an RBTree keyed off the start of the range
        self._ranges = RBTree(key=lambda x: x[0])

    def is_empty(self) -> bool:
        """Check if this collection is empty

        Returns:
            True iff there are no ranges in this collection
        """
        return self._ranges.is_empty()

    def contains(self, arange: typing.Tuple[int, int]) -> bool:
        """Check if a specific range overlaps any range in this collection

        Arguments:
            arange: The range to test for overlaps

        Returns:
            True iff at least one range in the collection covers at least one value in `arange`
        """

        start, end = arange
        lo = self._ranges.bisect_left(arange)
        if lo is not None:
            # There is something before start
            lo_start, lo_end = lo
            # lo_start is going to be less than or equal to start.
            # If range overlaps, start must be in lo
            if start < lo_end:
                return True

        hi = self._ranges.bisect_right(arange)
        if hi is not None:
            # There is something after start
            hi_start, hi_end = hi
            # hi_start is going to be greater than or equal to start
            # If range overlaps, hi_start must be in arange.
            if hi_start < end:
                return True

        return False

    def contains_value(self, value: int) -> bool:
        """Check if any range in this collection contains a value

        Arguments:
            value: The value to locate

        Returns:
            True iff there is a range in the collection which contains `value`
        """
        arange = (value, value + 1)

        # Only need to test left bisect
        # Value must equal start or be to the right
        lo = self._ranges.bisect_left(arange)
        if lo is not None:
            lo_start, lo_end = lo
            if value >= lo_start and value < lo_end:
                return True

        return False

    def find_closest_range(
        self, value: int
    ) -> typing.Tuple[typing.Optional[typing.Tuple[int, int]], bool]:
        """Find the range closest to a value

        Arguments:
            value: The value to locate

        Returns:
            - The closest range, or None if the collection is empty
            - True iff `value` is in that range
        """
        out = self._ranges.bisect_left((value, value + 1))
        if out is None:
            out = self._ranges.bisect_right((value, value + 1))
        return (out, out is not None and out[0] <= value < out[1])

    def add_range(self, arange: typing.Tuple[int, int]) -> None:
        """Add a range to the collection

        Arguments:
            arange: The range to insert
        """
        start, end = arange
        if start >= end:
            raise ValueError(f"Invalid range {arange}")

        lo = self._ranges.bisect_left(arange)

        if lo is not None:
            # We are not the lowest range
            lo_start, lo_end = lo
            if lo_start == start and lo_end == end:
                # We are already in the collection.  Happy happy joy joy.
                return
            # There's at least one range below us.
            # Since the tree keys off the start of ranges,
            # we can only collide with this one element
            if start >= lo_start and start <= lo_end:
                # We collide with lo.
                # Remove it from the tree, and absorb it into ourself.
                self._ranges.remove(lo)
                if lo_start < start:
                    start = lo_start
                if lo_end > end:
                    end = lo_end

        hi = self._ranges.bisect_right(arange)
        while hi is not None:
            hi_start, hi_end = hi
            if hi_start > end:
                # We don't overlap with hi.
                # We can stop slurping things up.
                break
            if hi_start < start:
                start = hi_start
            if hi_end > end:
                end = hi_end
            self._ranges.remove(hi)
            hi = self._ranges.bisect_right(arange)

        self._ranges.insert((start, end))

    def update(self, other: RangeCollection) -> None:
        """Add all ranges from another collection to this collection

        Arguments:
            other: The collection containing ranges to add
        """
        for rng in other:
            self.add_range(rng)

    def add_value(self, value: int) -> None:
        """Add a singleton range to the collection

        Arguments:
            value: The value for which to add a singleton
        """
        self.add_range((value, value + 1))

    def remove_range(self, arange: typing.Tuple[int, int]) -> None:
        """Remove any overlaps between a specific range and this collection.

        This doesn't remove a specific range;
        rather, it removes any intersections between items
        of this collection and `arange`.

        Arguments:
            arange: The range to remove
        """
        start, end = arange
        if start >= end:
            raise ValueError(f"Invalid range {arange}")
        lo = self._ranges.bisect_left(arange)
        if lo is not None:
            # We are not the lowest range
            lo_start, lo_end = lo
            if lo_start == start and lo_end == lo:
                # We exactly match an existing range
                self._ranges.remove(arange)
                return
            if start >= lo_start and end <= lo_end:
                # We collide with lo.
                # Remove lo and add the remainder back
                self._ranges.remove(lo)
                if start > lo_start:
                    # There's a bit at the beginning we need to replace
                    self._ranges.insert((lo_start, start))
                if end < lo_end:
                    # There's a bit at the end we need to replace
                    self._ranges.insert((end, lo_end))
                    # We don't need to keep going; everything will be higher.
                    return

        hi = self._ranges.bisect_right(arange)
        while hi is not None:
            hi_start, hi_end = hi
            if hi_start >= end:
                # We don't overlap with hi; we're out of ranges
                break
            self._ranges.remove(hi)
            if end < hi_end:
                # There's a bit left over at the end
                self._ranges.insert((end, hi_end))
                # We don't need to keep going; everything else will be higher.
                return
            hi = self._ranges.bisect_right(arange)

    def get_missing_ranges(
        self, arange: typing.Tuple[int, int]
    ) -> typing.List[typing.Tuple[int, int]]:
        """Find the subset of a given range not covered by this collection"""
        out = list()
        start, end = arange

        lo = self._ranges.bisect_left((start, end))
        if lo is not None:
            # There is an item below us
            lo_start, lo_end = lo
            # lo_start will be less than or equal to start,
            # so there can't be a missing range before lo.
            # We do care if there's an overlap
            if lo_end > start:
                # arange and lo overlap.  Remove the overlap
                start = lo_end

        hi = self._ranges.bisect_right((start, end))
        while hi is not None:
            # There is an item above us
            hi_start, hi_end = hi
            if hi_start >= end:
                # The item is so far above that it can't intersect
                # Anything else will be higher, so we're done.
                break
            if hi_start > start:
                # hi doesn't cover the start of arange
                # We found a missing range
                out.append((start, hi_start))
            start = hi_end
            hi = self._ranges.bisect_right((start, end))
        if start < end:
            # There's still a bit left
            out.append((start, end))
        return out

    @property
    def ranges(self) -> typing.List[typing.Tuple[int, int]]:
        """The list of ranges in order by start"""
        return list(self._ranges.values())

    def __iter__(self):
        return iter(self._ranges.values())


class SparseIO(io.BufferedIOBase):
    """Sparse memory-backed IO stream object

    BytesIO requires a contiguous bytes object.
    If you have a large, sparse memory image,
    it will gladly OOM your analysis.

    This uses an RBTree in the same manner as
    RangeCollection to maintain a non-contiguous
    sequence of bytes.
    Any data outside those ranges is assumed to be zero.

    This is used by AngrEmulator to load programs,
    and makes it possible to load sparse memory images
    covering large swaths of the address space into CLE.
    """

    def __init__(self):
        self._ranges = RBTree(key=lambda x: x[0])
        self._pos = 0
        self.size = 0

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def seek(self, pos: int, whence: int = 0) -> int:
        if not isinstance(pos, int):
            raise TypeError(f"pos must be an int; got a {type(pos)}")

        if not isinstance(whence, int):
            raise TypeError(f"whence must be an int; got a {type(whence)}")

        if whence < 0 or whence > 2:
            raise ValueError(f"Invalid whence {whence}")

        if whence == 0:
            # Relative to start of file
            self._pos = pos
        elif whence == 1:
            # Relative to current file
            self._pos += pos
        else:
            # Relative to end of file
            self._pos = self.size + pos

        return self._pos

    def read(self, size: typing.Optional[int] = -1) -> bytes:
        if size is None or size == -1:
            size = self.size
        start = self._pos
        end = start + size
        data = bytearray()

        lo = self._ranges.bisect_left((start, end, None))
        if lo is not None:
            # We are not below the lowest segment
            lo_start, lo_end, lo_data = lo
            if lo_end > start:
                # We overlap lo
                # lo_start is guaranteed to be less than or equal to start
                a = start - lo_start
                data += lo_data[a:]
                start = lo_end

        hi = self._ranges.bisect_right((start, end, None))
        while hi is not None:
            # We are not the right-most
            hi_start, hi_end, hi_data = hi
            if hi_start >= end:
                break
            if hi_start > start:
                data += b"\x00" * (hi_start - start)
                start = hi_start
            a = min(hi_end, end) - hi_start
            data += hi_data[:a]
            start = a + hi_start
            hi = self._ranges.bisect_right((start, end, None))

        if start < end:
            data += b"\x00" * (end - start)

        self._pos = end
        return bytes(data)

    def read1(self, size: int = -1) -> bytes:
        return self.read(size=size)

    def write(self, data) -> int:
        # NOTE: `data` is a bytes-like.
        # Python doesn't add a way to annotate bytes-like types
        # until 3.12
        data = bytearray(data)
        start = self._pos
        end = start + len(data)
        o_start = start
        o_end = end

        lo = self._ranges.bisect_left((start, end))
        if lo is not None:
            # We are not the lowest segment
            lo_start, lo_end, lo_data = lo
            if lo_end > start:
                # We overlap lo
                # Because of how bisect works here,
                # lo_start must be less or equal to start
                self._ranges.remove(lo)

                a = start - lo_start
                b = end - lo_start

                lo_data[a:b] = data
                data = lo_data

                start = lo_start
                if lo_end > end:
                    end = lo_end

        hi = self._ranges.bisect_right((start, end))
        while hi is not None:
            hi_start, hi_end, hi_data = hi
            # We are not the highest segment
            if hi_start >= end:
                # We do not overlap hi
                break

            # We overlap hi
            # Because of how bisect works here,
            # hi_start must be greater or equal to start
            self._ranges.remove(hi)
            if hi_end > end:
                a = end - hi_start
                data += hi_data[a:]
                end = hi_end
            hi = self._ranges.bisect_right((start, end))

        if len(data) != end - start:
            raise Exception(
                f"Buffer contains {len(data)} bytes, but have ({hex(start)}, {hex(end)}), starting with ({hex(o_start)}, {hex(o_end)})"
            )
        if end > self.size:
            self.size = end
        self._pos = end
        self._ranges.insert((start, end, data))
        return len(data)
