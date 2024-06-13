import io
import os
import re
import subprocess
import typing
import unittest

from sphinx import application, errors


class DetailedCalledProcessError(Exception):
    def __init__(self, error: subprocess.CalledProcessError):
        self.error = error

    def __str__(self) -> str:
        return f"{self.error.__str__()}\n\nstdout:\n{self.error.stdout.decode()}\n\nstderr:\n{self.error.stderr.decode()}"


class ScriptIntegrationTest(unittest.TestCase):
    def command(
        self, cmd: str, stdin: typing.Optional[str] = None, error: bool = True
    ) -> typing.Tuple[str, str]:
        """Run the given command and return the output.

        Arguments:
            cmd: The command to run.
            stdin: Optional input string.
            error: If `True` raises an exception if the command fails,
                otherwise just returns stdout/stderr as if it had succeeded.

        Returns:
            The `(stdout, stderr)` of the process as strings.
        """

        input = stdin.encode() if stdin else None

        cwd = os.path.abspath(os.path.dirname(__file__))

        try:
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
        except subprocess.CalledProcessError as e:
            if error:
                raise DetailedCalledProcessError(e)
            else:
                return e.stdout.decode(), e.stderr.decode()

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

    def assertLineContainsStrings(self, output: str, *strings) -> None:
        """Assert that any line contains all of these strings.

        Arguments:
            output: The output to check.
            strings: One or more strings to match.

        Raises:
            `AssertionError` if no single line in `output` matches all
            `strings`.
        """

        for line in output.split("\n"):
            for string in strings:
                if not (string in line):
                    break
            else:
                return

        import pdb

        pdb.set_trace()
        raise AssertionError(
            f"no line in string contains all of `{strings}`:\n\n{output.strip()}"
        )

    def assertLineContainsRegexes(self, output: str, *matches) -> None:
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
                if re.search(match, line) is None:
                    break
            else:
                return

        raise AssertionError(
            f"no line in string contains all of `{matches}`:\n\n{output.strip()}"
        )


class SquareTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command("python3 basic_harness.py square.bin")

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
            "imul edi, edi",
            '"pc": 4096',
            '"color": 1',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "edi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "write-def-prob",
            "imul edi, edi",
            '"pc": 4096',
            '"color": 2',
            '"use": false',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "edi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-flow-prob",
            "mov eax, edi",
            '"pc": 4099',
            '"color": 2',
            '"use": true',
            '"new": false',
            '"prob": 1.0',
            '"reg_name": "edi"',
        )

    def run_test(self, arch=None):
        def test_output(number, arch):
            if arch is None:
                arch = ""
            else:
                arch = "." + arch
            stdout, _ = self.command(f"python3 square{arch}.py {number}")

            self.assertLineContainsStrings(stdout, hex(number**2))

        test_output(5, arch)
        test_output(1337, arch)
        test_output(65535, arch)

    def test_square_amd64(self):
        self.run_test()

    def test_square_aarch64(self):
        self.run_test(arch="aarch64")

    def test_square_armel(self):
        self.run_test(arch="armel")

    def test_square_armhf(self):
        self.run_test(arch="armhf")

    def test_square_mips(self):
        self.run_test(arch="mips")


class StackTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command("python3 basic_harness.py stack.bin")

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
            "add rdi, rdx",
            '"pc": 4096',
            '"color": 1',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "rdi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
            "add rdi, rdx",
            '"pc": 4096',
            '"color": 2',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "rdx"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "write-def-prob",
            "add rdi, rdx",
            '"pc": 4096',
            '"color": 3',
            '"use": false',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "rdi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-flow-prob",
            "lea rax, [rdi + r8]",
            '"pc": 4099',
            '"color": 3',
            '"use": true',
            '"new": false',
            '"prob": 1.0',
            '"reg_name": "rdi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
            "lea rax, [rdi + r8]",
            '"pc": 4099',
            '"color": 4',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "r8"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "write-def-prob",
            "lea rax, [rdi + r8]",
            '"pc": 4099',
            '"color": 5',
            '"use": false',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "rax"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-flow-prob",
            "add rax, qword ptr [rsp + 8]",
            '"pc": 4103',
            '"color": 5',
            '"use": true',
            '"new": false',
            '"prob": 1.0',
            '"reg_name": "rax"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
            "add rax, qword ptr [rsp + 8]",
            '"pc": 4103',
            '"color": 6',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "rsp"',
        )

        self.assertLineContainsStrings(stderr, '"pointer"', '"base": "rsp"')

        self.assertLineContainsStrings(
            stderr, '{"4096": 1, "4099": 1, "4103": 1}', "coverage"
        )

    def test_stack(self):
        stdout, _ = self.command("python3 stack.py")
        self.assertLineContainsStrings(stdout, "rax", "0xaaaaaaaa")


class StructureTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command("python3 basic_harness.py struct.bin")

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
            "mov eax, dword ptr",
            '"pc": 4113',
            '"color": 1',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "rdi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "MemoryUnavailableProbHint",
            "mem_unavailable-prob",
            "mov eax, dword ptr [rdi + 0x18]",
            '"pc": 4113',
            '"prob": 1.0',
            '"is_read": true',
            '"base_reg_name": "rdi"',
            '"index_reg_name": "None"',
            '"offset": 24',
            '"scale": 1',
        )

        self.assertLineContainsStrings(
            stderr, "from_instruction", "6w8=", "4096", "to_instruction", "i0cY", "4113"
        )
        self.assertLineContainsStrings(stderr, '{"4096": 1, "4113": 1}', "coverage")
        self.assertLineContainsStrings(stderr, "address", "4113", "code_reachable")
        self.assertLineContainsStrings(stderr, "address", "4098", "code_reachable")
        self.assertLineContainsStrings(stderr, "address", "4120", "code_reachable")


class BranchTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command("python3 basic_harness.py branch.bin")

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
            "xor eax, eax",
            '"pc": 4096',
            '"color": 1',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "eax"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
            "cmp rdi, 0x64",
            '"pc": 4098',
            '"color": 2',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "rdi"',
        )
        self.assertLineContainsStrings(
            stderr, '{"4096": 1, "4098": 1, "4102": 1}', "coverage"
        )

    def run_branch(self, arch=None, reg="eax"):
        if arch is None:
            arch = ""
        else:
            arch = "." + arch
        stdout, _ = self.command(f"python3 branch{arch}.py 99")
        self.assertLineContainsStrings(stdout, reg, "0x0")

        stdout, _ = self.command(f"python3 branch{arch}.py 100")
        self.assertLineContainsStrings(stdout, reg, "0x1")

        stdout, _ = self.command(f"python3 branch{arch}.py 101")
        self.assertLineContainsStrings(stdout, reg, "0x0")

    def test_branch_x86(self):
        self.run_branch()

    def test_branch_aarch64(self):
        self.run_branch(arch="aarch64", reg="x0")

    def test_branch_armel(self):
        self.run_branch(arch="armel", reg="r0")

    def test_branch_armhf(self):
        self.run_branch(arch="armhf", reg="r0")

    def test_branch_mips(self):
        self.run_branch(arch="mips", reg="v0")


class HookingTests(ScriptIntegrationTest):
    def test_hooking(self):
        stdout, _ = self.command("python3 hooking.py", stdin="foo bar baz")
        self.assertLineContainsStrings(stdout, "foo bar baz")


try:
    import unicornafl
except ImportError:
    unicornafl = None


class FuzzTests(ScriptIntegrationTest):
    def test_fuzz(self):
        stdout, _ = self.command("python3 fuzz.py")
        self.assertLineContainsStrings(stdout, "eax", "0x0")

        _, stderr = self.command("python3 fuzz.py -c")
        self.assertLineContainsStrings(stderr, "UC_ERR_WRITE_UNMAPPED")

    @unittest.skipUnless(unicornafl, "afl++ must be installed from source")
    def test_fuzzing(self):
        stdout, _ = self.command(
            "afl-showmap -U -m none -o /dev/stdout -- python3 afl_fuzz.py fuzz_inputs/good_input",
            error=False,
        )
        self.assertLineContainsStrings(stdout, "001445:1")
        self.assertLineContainsStrings(stdout, "003349:1")
        self.assertLineContainsStrings(stdout, "014723:1")
        self.assertLineContainsStrings(stdout, "022192:1")
        self.assertLineContainsStrings(stdout, "032232:1")
        self.assertLineContainsStrings(stdout, "032233:1")
        self.assertLineContainsStrings(stdout, "032234:1")
        self.assertLineContainsStrings(stdout, "040896:1")


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
