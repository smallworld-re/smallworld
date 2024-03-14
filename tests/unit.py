import unittest

from smallworld import emulators, initializers, instructions, state


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
