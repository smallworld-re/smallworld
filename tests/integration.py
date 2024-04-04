import io
import os
import re
import subprocess
import typing
import unittest

from sphinx import application, errors


class ScriptIntegrationTest(unittest.TestCase):
    def command(
        self, cmd: str, stdin: typing.Optional[str] = None
    ) -> typing.Tuple[str, str]:
        """Run the given command and return the output.

        Arguments:
            cmd: The command to run.

        Returns:
            The `(stdout, stderr)` of the process as strings.
        """

        input = stdin.encode() if stdin else None

        cwd = os.path.abspath(os.path.dirname(__file__))

        process = subprocess.run(
            cmd,
            cwd=cwd,
            shell=True,
            check=True,
            input=input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        return process.stdout.decode(), process.stderr.decode()

    def assertContains(self, output: str, match: str) -> None:
        """Assert that output contains a given regex.

        Arguments:
            output: The output to check.
            match: The regex to match.

        Raises:
            `AssertionError` if `match` is not found in `output`.
        """

        if re.search(match, output) is None:
            raise AssertionError(
                f"string does not contain `{match}`:\n\n{output.strip()}"
            )

    def assertLineContains(self, output: str, *matches) -> None:
        """Assert that any line contains some combination of regexes.

        Arguments:
            output: The output to check.
            matches: One or more regexes to match.

        Raises:
            `AssertionError` if no single line in `output` matches all
            `matches`.
        """

        for line in output.split("\n"):
            for match in matches:
                if re.search(match, output) is None:
                    break
            else:
                return

        raise AssertionError(
            f"no line in string contains all of `{matches}`:\n\n{output.strip()}"
        )


class SquareTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command("python3 basic_harness.py square.bin")
        self.assertLineContains(stderr, "edi", "imul edi, edi", "InputUseHint")
        self.assertLineContains(stderr, '{"4096": 1, "4099": 1}', "coverage")

    def test_square(self):
        def test_output(number):
            stdout, _ = self.command(f"python3 square.py {number}")

            self.assertContains(stdout, hex(number**2))

        test_output(5)
        test_output(1337)
        test_output(65535)


class StackTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command("python3 basic_harness.py stack.bin")
        self.assertLineContains(stderr, "rdi", "add rdi, rdx", "InputUseHint")
        self.assertLineContains(stderr, "rdx", "add rdi, rdx", "InputUseHint")
        self.assertLineContains(
            stderr, "r8", re.escape("lea rax, [rdi + r8]"), "InputUseHint"
        )
        self.assertLineContains(
            stderr, "rsp", re.escape("add rax, qword ptr [rsp + 8]"), "InputUseHint"
        )
        self.assertLineContains(stderr, '{"4096": 1, "4099": 1, "4103": 1}', "coverage")

    def test_stack(self):
        stdout, _ = self.command("python3 stack.py")
        self.assertLineContains(stdout, "rax", "0xaaaaaaaa")


class StructureTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command("python3 basic_harness.py struct.bin")
        self.assertLineContains(
            stderr, "rdi", re.escape("mov eax, dword ptr [rdi + 0x18]"), "InputUseHint"
        )

        self.assertLineContains(
            stderr, "from_instruction", "6w8=", "4096", "to_instruction", "i0cY", "4113"
        )
        self.assertLineContains(stderr, '{"4096": 1, "4113": 1}', "coverage")
        self.assertLineContains(stderr, "address", "4113", "code_reachable")
        self.assertLineContains(stderr, "address", "4098", "code_reachable")
        self.assertLineContains(stderr, "address", "4120", "code_reachable")


class BranchTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command("python3 basic_harness.py branch.bin")
        self.assertLineContains(stderr, "eax", "xor eax, eax", "InputUseHint")
        self.assertLineContains(stderr, "rdi", "cmp rdi, 0x64", "InputUseHint")
        self.assertLineContains(stderr, '{"4096": 1, "4098": 1, "4102": 1}', "coverage")

    def test_branch(self):
        stdout, _ = self.command("python3 branch.py 99")
        self.assertLineContains(stdout, "eax", "0x0")

        stdout, _ = self.command("python3 branch.py 100")
        self.assertLineContains(stdout, "eax", "0x1")

        stdout, _ = self.command("python3 branch.py 101")
        self.assertLineContains(stdout, "eax", "0x0")


class HookingTests(ScriptIntegrationTest):
    def test_hooking(self):
        stdout, _ = self.command("python3 hooking.py", stdin="foo bar baz")
        self.assertLineContains(stdout, "foo bar baz")


try:
    import unicornafl
except ImportError:
    unicornafl = None


class FuzzTests(ScriptIntegrationTest):
    @unittest.skipUnless(unicornafl, "afl++ must be installed from source")
    def test_fuzz(self):
        stdout, _ = self.command("python3 fuzz.py")
        self.assertLineContains(stdout, "eax", "0x0")

        _, stderr = self.command("python3 fuzz.py -c")
        self.assertLineContains(stderr, "UC_ERR_WRITE_UNMAPPED")

    @unittest.skipUnless(unicornafl, "afl++ must be installed from source")
    def test_fuzzing(self):
        stdout, _ = self.command(
            "afl-showmap -U -m none -o /dev/stdout -- python3 afl_fuzz.py fuzz_inputs/good_input"
        )
        self.assertLineContains(stdout, "001445:1")
        self.assertLineContains(stdout, "003349:1")
        self.assertLineContains(stdout, "014723:1")
        self.assertLineContains(stdout, "022192:1")
        self.assertLineContains(stdout, "032232:1")
        self.assertLineContains(stdout, "032233:1")
        self.assertLineContains(stdout, "032234:1")
        self.assertLineContains(stdout, "040896:1")


class DocumentationTests(unittest.TestCase):
    def test_documentation_build(self):
        """Make sure that the documentation builds without error.

        This gathers all errors from the build and raises them at once so you
        don't have to debug one at a time.
        """

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        source = os.path.join(root, "docs")
        config = source
        build = os.path.join(source, "build")
        doctree = os.path.join(build, "doctrees")

        warnings = io.StringIO()

        app = application.Sphinx(
            source, config, build, doctree, "html", status=None, warning=warnings
        )
        app.build()

        warnings.flush()
        warnings.seek(0)
        warnings = warnings.read().strip()

        if warnings:
            raise errors.SphinxWarning(f"\n\n{warnings}")


if __name__ == "__main__":
    unittest.main()
