import signal
import typing
import unittest

from smallworld import emulators, initializers, instructions, state


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

        def initialize(
            self, initializer: initializers.Initializer, override: bool = False
        ) -> None:
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
                301: "argv[0]",
                297: "argv[1]",
                288: "stack alignment padding bytes",
                280: "null terminator of argv array",
                272: "pointer to argv[1]",
                264: "pointer to argv[0]",
                256: "argc",
            },
        )
        self.assertEqual(
            s.value,
            b"\x02\x00\x00\x00\x00\x00\x00\x00-\x01\x00\x00\x00\x00\x00\x00)\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00BBBBAAA",
        )


class UnicornEmulatorTests(unittest.TestCase):
    def test_write_memory_not_page_aligned(self):
        emu = emulators.UnicornEmulator("x86", "64")

        address = 0x1800
        value = b"A" * 32

        emu.write_memory(address, value)
        read = emu.read_memory(address, len(value))

        self.assertEqual(read, value)

    def test_write_memory_multipage_not_page_aligned(self):
        emu = emulators.UnicornEmulator("x86", "64")

        address = 0x1800
        value = b"A" * 0x1200

        emu.write_memory(address, value)
        read = emu.read_memory(address, len(value))

        self.assertEqual(read, value)

    def test_write_memory_multipage_span_less_than_page_size(self):
        """Allocation less than a page, but spans multiple pages."""

        emu = emulators.UnicornEmulator("x86", "64")

        address = 0x1800
        value = b"A" * 0x850

        emu.write_memory(address, value)
        read = emu.read_memory(address, len(value))

        self.assertEqual(read, value)

    def test_write_memory_page_overlapping_explicit(self):
        """Overlapping writes start in the same page."""

        emu = emulators.UnicornEmulator("x86", "64")

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

        emu = emulators.UnicornEmulator("x86", "64")

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

        emu = emulators.UnicornEmulator("x86", "64")

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

        emu = emulators.UnicornEmulator("x86", "64")

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


class InstructionTests(unittest.TestCase):
    def test_semantics_nop(self):
        # nop
        i = instructions.Instruction.from_bytes(b"\x90", 0x1000, "x86", "64")

        self.assertEqual(len(i.reads), 0)
        self.assertEqual(len(i.writes), 0)

    def test_semantics_register_cmp(self):
        # cmp eax, ebx
        i = instructions.Instruction.from_bytes(b"\x39\xd8", 0x1000, "x86", "64")

        reads = [getattr(o, "name", None) for o in i.reads]
        writes = [getattr(o, "name", None) for o in i.writes]

        self.assertIn("eax", reads)
        self.assertIn("ebx", reads)
        self.assertIn("rflags", writes)

    def test_semantics_memory_cmp(self):
        # cmp eax, [rbx + 0x10]
        i = instructions.Instruction.from_bytes(b"\x3b\x43\x10", 0x1000, "x86", "64")

        reads = [getattr(o, "name", None) for o in i.reads]
        writes = [getattr(o, "name", None) for o in i.writes]

        self.assertIn("eax", reads)
        self.assertIn("rbx", reads)

        for read in reads:
            if type(read) is instructions.x86MemoryReferenceOperand:
                self.assertEqual(read.base, "rbx")
                self.assertEqual(read.index, None)
                self.assertEqual(read.scale, 1)
                self.assertEqual(read.offset, 0x10)
                self.assertEqual(read.size, 4)

        self.assertIn("rflags", writes)

    def test_semantics_register_mov(self):
        # cmp eax, ebx
        i = instructions.Instruction.from_bytes(b"\x89\xd8", 0x1000, "x86", "64")

        reads = [getattr(o, "name", None) for o in i.reads]
        writes = [getattr(o, "name", None) for o in i.writes]

        self.assertIn("ebx", reads)
        self.assertIn("eax", writes)

    def test_semantics_memory_mov_complex(self):
        # mov eax, [eax+ecx*8+0x10]
        i = instructions.Instruction.from_bytes(
            b"\x8b\x44\xc8\x10", 0x1000, "x86", "64"
        )

        reads = [getattr(o, "name", None) for o in i.reads]
        writes = [getattr(o, "name", None) for o in i.writes]

        self.assertIn("rax", reads)
        self.assertIn("rcx", reads)
        self.assertIn("eax", writes)

        for read in reads:
            if type(read) is instructions.x86MemoryReferenceOperand:
                self.assertEqual(read.base, "rax")
                self.assertEqual(read.index, "rcx")
                self.assertEqual(read.scale, 8)
                self.assertEqual(read.offset, 0x10)
                self.assertEqual(read.size, 4)

    def test_x86_memory_reference_operand_serialization(self):
        a = instructions.x86MemoryReferenceOperand("rax", "rbx", 1, 0)
        self.assertEqual(a.base, "rax")
        self.assertEqual(a.index, "rbx")
        self.assertEqual(a.scale, 1)
        self.assertEqual(a.offset, 0)
        json = a.to_json()
        b = instructions.x86MemoryReferenceOperand.from_json(json)
        self.assertEqual(b.base, "rax")
        self.assertEqual(b.index, "rbx")
        self.assertEqual(b.scale, 1)
        self.assertEqual(b.offset, 0)


if __name__ == "__main__":
    unittest.main()
