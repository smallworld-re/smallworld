import unittest

from smallworld import emulators, initializers, state


class StateTests(unittest.TestCase):
    class TestValue(state.Value):
        def __init__(self):
            super().__init__()

            self.value = None

        def get(self):
            return self.value

        def set(self, value) -> None:
            self.value = value

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

    def test_getitem_valid(self):
        s = state.State()
        v = self.TestValue()

        s.map(v, "foo")

        self.assertEqual(s["foo"], s.foo.get())

    def test_getitem_invalid(self):
        s = state.State()

        with self.assertRaises(ValueError):
            s["foo"]

    def test_setitem_valid(self):
        s = state.State()
        v = self.TestValue()

        s.map(v, "foo")

        s["foo"] = 3

        self.assertEqual(s["foo"], 3)
        self.assertEqual(s["foo"], s.foo.get())

    def test_setitem_invalid(self):
        s = state.State()

        with self.assertRaises(ValueError):
            s["foo"] = 3

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


if __name__ == "__main__":
    unittest.main()
