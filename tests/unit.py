import signal
import typing
import unittest

import claripy

from smallworld import emulators, platforms, state, utils


class MockConcreteEmulator(emulators.Emulator):
    pass


class assertTimeout:
    """Raise if the enclosed block takes longer than the given timeout.

    This should be used as a context manager.

    Arguments:
        timeout: Maximum time in seconds.
        message: Error message.

    Raises:
        `AssertionError` if the enclosed block takes longer than `timeout`
        seconds.
    """

    def __init__(self, timeout: int, message: typing.Optional[str] = None):
        if message is None:
            message = f"took too long (>{timeout}s)"

        self.timeout = timeout
        self.message = message

    def handle_timeout(self, signum, frame):
        raise AssertionError(self.message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.timeout)

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.alarm(0)


class StateTests(unittest.TestCase):
    def assertClaripyEqual(self, actual, expected, msg=None):
        if not isinstance(actual, claripy.ast.bv.BV):
            self.fail(msg=f"Actual value {actual} is not a bitvector expression")

        if not isinstance(expected, claripy.ast.bv.BV):
            self.fail(msg=f"Expected value {expected} is not a bitvector expression")
        if msg is None:
            msg = f"Expected {expected}, but got {actual}"
        return self.assertTrue(expected.structurally_match(actual), msg=msg)

    def test_register_assignment(self):
        foo = state.Register("foo", 4)
        foo_c = 0xAAAAAAAA
        foo_v = claripy.BVV(foo_c, 32)
        foo_s = claripy.BVS("foo", 32, explicit_name=True)
        bad_s = claripy.BVS("bad", 1)

        # Integer without label
        foo.set(foo_c)
        foo.set_label(None)
        self.assertEqual(foo.get(), foo_c)
        self.assertClaripyEqual(foo.to_symbolic(platforms.Byteorder.BIG), foo_v)

        # Integer with label
        foo.set(foo_c)
        foo.set_label("foo")
        self.assertEqual(foo.get(), foo_c)
        self.assertClaripyEqual(foo.to_symbolic(platforms.Byteorder.BIG), foo_s)

        # Symbolic without label
        foo.set(foo_v)
        foo.set_label(None)
        self.assertClaripyEqual(foo.get(), foo_v)
        self.assertClaripyEqual(foo.to_symbolic(platforms.Byteorder.BIG), foo_v)

        # Sybolic with label
        foo.set(foo_v)
        foo.set_label("foo")
        self.assertClaripyEqual(foo.get(), foo_v)
        self.assertClaripyEqual(foo.to_symbolic(platforms.Byteorder.BIG), foo_s)

        # Invalid symbolic value
        with self.assertRaises(ValueError):
            foo.set(bad_s)

    def test_register_aliasing(self):
        foo = state.Register("foo", 4)
        bar = state.RegisterAlias("bar", foo, 2, 2)
        foo_c = 0xAAAAAAAA
        bar_c = 0xBBBB
        foo_v = claripy.BVV(foo_c, 32)
        bar_v = claripy.BVV(bar_c, 16)
        foo_s = claripy.BVS("foo", 32)
        bar_s = claripy.BVS("bar", 16)

        # Test integer/integer
        foo.set(foo_c)
        bar.set(bar_c)
        self.assertEqual(foo.get(), (foo_c & 0xFFFF) | (bar_c << 16))
        self.assertEqual(bar.get(), bar_c)

        # Test symbol/integer
        foo.set(foo_s)
        bar.set(bar_c)
        res_s = claripy.Concat(bar_v, foo_s[15:0])

        self.assertClaripyEqual(res_s, foo.get())
        self.assertClaripyEqual(bar_v, bar.get())

        # Test integer/symbol
        foo.set(foo_c)
        bar.set(bar_s)
        res_s = claripy.Concat(bar_s, foo_v[15:0])

        self.assertClaripyEqual(res_s, foo.get())
        self.assertClaripyEqual(bar_s, bar.get())

        # Test symbol/symbol
        foo.set(foo_s)
        bar.set(bar_s)
        res_s = claripy.Concat(bar_s, foo_s[15:0])

        self.assertClaripyEqual(res_s, foo.get())
        self.assertClaripyEqual(bar_s, bar.get())


class UtilsTests(unittest.TestCase):
    def test_range_collection_add(self):
        rc = utils.RangeCollection()
        a = (4, 9)
        b = (4, 6)  # entirely contained
        c = (9, 12)  # hitting right bound
        d = (2, 4)  # hitting left bound
        e = (1, 3)  # across left bound
        f = (10, 15)  # across right bound
        rc.add_range(a)
        compare = [(4, 9)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(b)
        compare = [(4, 9)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(c)
        compare = [(4, 12)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(d)
        compare = [(2, 12)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(e)
        compare = [(1, 12)]
        self.assertEqual(rc.ranges, compare)

        rc.add_range(f)
        compare = [(1, 15)]
        self.assertEqual(rc.ranges, compare)

        rc.add_value(18)
        self.assertEqual(rc.ranges, [(1, 15), (18, 19)])
        rc.add_value(16)
        self.assertEqual(rc.ranges, [(1, 15), (16, 17), (18, 19)])
        rc.add_value(15)
        self.assertEqual(rc.ranges, [(1, 17), (18, 19)])

    def test_range_collection_missing(self):
        rc = utils.RangeCollection()
        a = rc.get_missing_ranges((1, 3))
        self.assertEqual(a, [(1, 3)])

        start = [(22, 25), (2, 4), (8, 13), (19, 22), (13, 15), (29, 32)]
        for i in start:
            rc.add_range(i)

        self.assertEqual(rc.ranges, [(2, 4), (8, 15), (19, 25), (29, 32)])

        # Inside a range
        a = rc.get_missing_ranges((8, 15))
        self.assertEqual(a, [])
        a = rc.get_missing_ranges((8, 12))
        self.assertEqual(a, [])
        a = rc.get_missing_ranges((9, 15))
        self.assertEqual(a, [])
        a = rc.get_missing_ranges((9, 12))
        self.assertEqual(a, [])

        # Across a range
        a = rc.get_missing_ranges((10, 16))
        self.assertEqual(a, [(15, 16)])
        a = rc.get_missing_ranges((10, 19))
        self.assertEqual(a, [(15, 19)])
        a = rc.get_missing_ranges((10, 26))
        self.assertEqual(a, [(15, 19), (25, 26)])
        a = rc.get_missing_ranges((10, 40))
        self.assertEqual(a, [(15, 19), (25, 29), (32, 40)])

        a = rc.get_missing_ranges((16, 17))
        self.assertEqual(a, [(16, 17)])

    def test_range_collection_removal(self):
        pass

    def test_range_collection_find(self):
        # find closest
        rc = utils.RangeCollection()
        start = [(22, 25), (56, 70), (2, 4), (19, 22), (35, 41)]
        for i in start:
            rc.add_range(i)
        self.assertEqual(rc.ranges, [(2, 4), (19, 25), (35, 41), (56, 70)])

        a, b = rc.find_closest_range(3)
        self.assertEqual(a, (2, 4))
        self.assertEqual(b, True)
        a, b = rc.find_closest_range(8)
        self.assertEqual(a, (2, 4))
        self.assertEqual(b, False)
        a, b = rc.find_closest_range(19)
        self.assertEqual(a, (19, 25))
        self.assertEqual(b, True)
        a, b = rc.find_closest_range(25)
        self.assertEqual(a, (19, 25))
        self.assertEqual(b, False)
        a, b = rc.find_closest_range(1)
        self.assertEqual(a, (2, 4))
        self.assertEqual(b, False)

    def test_range_collection_update(self):
        rc = utils.RangeCollection()
        start = [(3, 4), (19, 25), (35, 41), (56, 70)]
        for i in start:
            rc.add_range(i)
        second = [(1, 2), (5, 10), (20, 26), (30, 36), (70, 72)]
        for i in second:
            rc.add_range(i)
        self.assertEqual(
            rc.ranges, [(1, 2), (3, 4), (5, 10), (19, 26), (30, 41), (56, 72)]
        )

    def test_range_collection_contains(self):
        rc = utils.RangeCollection()
        start = [(22, 25), (56, 70), (2, 4), (19, 22), (35, 41)]
        for i in start:
            rc.add_range(i)
        self.assertEqual(rc.ranges, [(2, 4), (19, 25), (35, 41), (56, 70)])

        a = rc.contains((0, 1))
        self.assertEqual(a, False)
        a = rc.contains((5, 6))
        self.assertEqual(a, False)

        a = rc.contains((1, 2))
        self.assertEqual(a, False)
        a = rc.contains((20, 27))
        self.assertEqual(a, True)
        a = rc.contains((20, 35))
        self.assertEqual(a, True)
        a = rc.contains((25, 27))
        self.assertEqual(a, False)


if __name__ == "__main__":
    unittest.main()
