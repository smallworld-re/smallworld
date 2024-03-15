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
        def get(self):
            pass

        def set(self, value) -> None:
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
        memory.set(b"A" * size)

        with assertTimeout(1):
            str(memory)


class InstructionTests(unittest.TestCase):
    def test_semantics_nop(self):
        # nop
        i = instructions.Instruction.from_bytes(b"\x90", 0x1000, "x86", "64")

        self.assertEqual(i.reads, [])
        self.assertEqual(i.writes, [])

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

        memory = i.reads[2]
        self.assertEqual(memory.base, "rbx")
        self.assertEqual(memory.index, None)
        self.assertEqual(memory.scale, 1)
        self.assertEqual(memory.offset, 0x10)
        self.assertEqual(memory.size, 4)

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

        memory = i.reads[2]
        self.assertEqual(memory.base, "rax")
        self.assertEqual(memory.index, "rcx")
        self.assertEqual(memory.scale, 8)
        self.assertEqual(memory.offset, 0x10)
        self.assertEqual(memory.size, 4)


if __name__ == "__main__":
    unittest.main()
