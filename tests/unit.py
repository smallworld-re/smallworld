import signal
import typing
import unittest

from smallworld import emulators, state, utils


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
    class TestValue(state.Value):
        @property
        def value(self):
            pass

        @value.setter
        def value(self, value) -> None:
            pass

        def load(self, emulator: emulators.Emulator, override: bool = True) -> None:
            pass

        def apply(self, emulator: emulators.Emulator) -> None:
            pass

        def __repr__(self) -> str:
            return f"{self.__class__.__name__}"

    def test_map_named(self):
        s = state.State()
        v = self.TestValue()

        s.map(v, "foo")

        self.assertTrue(hasattr(s, "foo"))
        self.assertEqual(s.foo, v)

    def test_map_nameless(self):
        s = state.State()
        v = self.TestValue()

        s.map(v)

        self.assertTrue(hasattr(s, "testvalue"))
        self.assertEqual(s.testvalue, v)

    def test_map_nameless_overlapping(self):
        s = state.State()
        v1 = self.TestValue()
        v2 = self.TestValue()

        s.map(v1)
        s.map(v2)

        self.assertTrue(hasattr(s, "testvalue"))
        self.assertEqual(s.testvalue, v1)

        self.assertTrue(hasattr(s, "testvalue1"))
        self.assertEqual(s.testvalue1, v2)

    def test_map_named_overlapping(self):
        s = state.State()
        v1 = self.TestValue()
        v2 = self.TestValue()

        s.map(v1, "foo")

        with self.assertRaises(ValueError):
            s.map(v2, "foo")

    def test_memory_repr_performance(self):
        size = 0x100000 * 32
        memory = state.Memory(address=0, size=size)
        memory.value = b"A" * size

        with assertTimeout(1):
            str(memory)

    def test_stack_init(self):
        foo = "AAA".encode("utf-8")
        bar = "BBBB".encode("utf-8")
        s = state.Stack.initialize_stack(argv=[foo, bar], address=0x100, size=0x30)
        sp = s.get_stack_pointer()
        self.assertEqual(sp, 248)
        self.assertDictEqual(
            s.label,
            {
                45: (3, "argv[0]"),
                41: (4, "argv[1]"),
                32: (9, "stack alignment padding bytes"),
                24: (8, "null terminator of argv array"),
                16: (8, "pointer to argv[1]"),
                8: (8, "pointer to argv[0]"),
                0: (8, "argc"),
            },
        )
        self.assertEqual(
            s.value,
            b"\x02\x00\x00\x00\x00\x00\x00\x00-\x01\x00\x00\x00\x00\x00\x00)\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BBBBAAA",
        )


class UnicornEmulatorTests(unittest.TestCase):
    def test_write_memory_not_page_aligned(self):
        emu = emulators.UnicornEmulator("x86", "64", "little")

        address = 0x1800
        value = b"A" * 32

        emu.write_memory(address, value)
        read = emu.read_memory(address, len(value))

        self.assertEqual(read, value)

    def test_write_memory_multipage_not_page_aligned(self):
        emu = emulators.UnicornEmulator("x86", "64", "little")

        address = 0x1800
        value = b"A" * 0x1200

        emu.write_memory(address, value)
        read = emu.read_memory(address, len(value))

        self.assertEqual(read, value)

    def test_write_memory_multipage_span_less_than_page_size(self):
        """Allocation less than a page, but spans multiple pages."""

        emu = emulators.UnicornEmulator("x86", "64", "little")

        address = 0x1800
        value = b"A" * 0x850

        emu.write_memory(address, value)
        read = emu.read_memory(address, len(value))

        self.assertEqual(read, value)

    def test_write_memory_page_overlapping_explicit(self):
        """Overlapping writes start in the same page."""

        emu = emulators.UnicornEmulator("x86", "64", "little")

        address1 = 0x1200
        value1 = b"A" * 0x32
        address2 = 0x1600
        value2 = b"B" * 0x32

        emu.write_memory(address1, value1)
        emu.write_memory(address2, value2)

        read1 = emu.read_memory(address1, len(value1))
        read2 = emu.read_memory(address2, len(value2))

        self.assertEqual(read1, value1)
        self.assertEqual(read2, value2)

    def test_write_memory_page_overlapping_implicit(self):
        """Overlapping writes start in different pages."""

        emu = emulators.UnicornEmulator("x86", "64", "little")

        address1 = 0x1200
        value1 = b"A" * 0x1000
        address2 = 0x2400
        value2 = b"B" * 0x32

        emu.write_memory(address1, value1)
        emu.write_memory(address2, value2)

        read1 = emu.read_memory(address1, len(value1))
        read2 = emu.read_memory(address2, len(value2))

        self.assertEqual(read1, value1)
        self.assertEqual(read2, value2)

    def test_write_memory_page_overlapping_extra_map(self):
        """Overlapping writes that require additional mappings."""

        emu = emulators.UnicornEmulator("x86", "64", "little")

        address1 = 0x1200
        value1 = b"A" * 32
        address2 = 0x1400
        value2 = b"B" * 0x1000

        emu.write_memory(address1, value1)
        emu.write_memory(address2, value2)

        read1 = emu.read_memory(address1, len(value1))
        read2 = emu.read_memory(address2, len(value2))

        self.assertEqual(read1, value1)
        self.assertEqual(read2, value2)

    def test_write_memory_page_contains_existing_maps(self):
        """Existing maps contained within the allocation."""

        emu = emulators.UnicornEmulator("x86", "64", "little")

        address1 = 0x1200
        value1 = b"A" * 32
        address2 = 0x3800
        value2 = b"B" * 32
        address3 = 0x1800
        value3 = b"C" * 0x1000

        emu.write_memory(address1, value1)
        emu.write_memory(address2, value2)
        emu.write_memory(address3, value3)

        read1 = emu.read_memory(address1, len(value1))
        read2 = emu.read_memory(address2, len(value2))
        read3 = emu.read_memory(address3, len(value3))

        self.assertEqual(read1, value1)
        self.assertEqual(read2, value2)
        self.assertEqual(read3, value3)


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

        a = rc.find_range(3)
        self.assertEqual(a, 0)
        a = rc.find_range(8)
        self.assertEqual(a, None)
        a = rc.find_range(19)
        self.assertEqual(a, 1)
        a = rc.find_range(25)
        self.assertEqual(a, None)

        a, b = rc.find_closest_range(3)
        self.assertEqual(a, 0)
        self.assertEqual(b, True)
        a, b = rc.find_closest_range(8)
        self.assertEqual(a, 0)
        self.assertEqual(b, False)
        a, b = rc.find_closest_range(19)
        self.assertEqual(a, 1)
        self.assertEqual(b, True)
        a, b = rc.find_closest_range(25)
        self.assertEqual(a, 1)
        self.assertEqual(b, False)
        a, b = rc.find_closest_range(1)
        self.assertEqual(a, -1)
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
