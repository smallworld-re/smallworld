import io
import os
import re
import subprocess
import typing
import unittest

from sphinx import application, errors

try:
    import unicornafl
except ImportError:
    unicornafl = None

try:
    import pandare
except ImportError:
    pandare = None


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

        # this means we didn't match any!  Let's figure out a little more detail

        # import pdb
        # pdb.set_trace()

        # best_count = 0
        # for line in output.split("\n"):
        #    count = 0
        # missing = []
        #    for string in strings:
        #        if string in line:
        #            count += 1
        #        else:
        #            missing.append(string)
        #    if count > best_count:
        #        best_count = count
        #        best_line = line
        #        best_missing = missing
        #
        # pdb.set_trace()

        raise AssertionError(
            f"no line in string contains all of `{strings}`:\n\n{output.strip()}"  # but best line with {count} of {len(strings)} is [{best_line}]"
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


class CallTests(ScriptIntegrationTest):
    def run_test(self, arch, signext=False):
        def test_output(number, res):
            stdout, _ = self.command(f"python3 call/call.{arch}.py {number}")
            self.assertLineContainsStrings(stdout, hex(res))

        if signext:
            test_output(0, 0xFFFFFFFFFFFFFFF9)
        else:
            test_output(0, 0xFFFFFFF9)
        test_output(1, 0x1)
        test_output(2, 0x9)
        test_output(101, 0x321)
        test_output(102, 0x21)
        test_output(65536, 0x21)

    def test_call_amd64(self):
        self.run_test("amd64")

    def test_call_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_call_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_call_aarch64(self):
        self.run_test("aarch64")

    def test_call_aarch64_angr(self):
        self.run_test("aarch64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_call_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_call_armel(self):
        self.run_test("armel")

    def test_call_armel_angr(self):
        self.run_test("armel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_call_armel_panda(self):
        self.run_test("armel.panda")

    def test_call_armhf(self):
        self.run_test("armhf")

    def test_call_armhf_angr(self):
        self.run_test("armhf.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_call_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_call_i386(self):
        self.run_test("i386")

    def test_call_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_call_i386_panda(self):
        self.run_test("i386.panda")

    def test_call_mips(self):
        self.run_test("mips")

    def test_call_mips_angr(self):
        self.run_test("mips.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_call_mips_panda(self):
        self.run_test("mips.panda")

    def test_call_mipsel(self):
        self.run_test("mipsel")

    def test_call_mipsel_angr(self):
        self.run_test("mipsel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_call_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_call_mips64_angr(self):
        self.run_test("mips64.angr", signext=True)

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_call_mips64_panda(self):
        self.run_test("mips64.panda", signext=True)

    def test_call_mips64el_angr(self):
        self.run_test("mips64el.angr", signext=True)

    def test_call_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_call_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_call_ppc64_angr(self):
        self.run_test("ppc64.angr", signext=True)

    def test_call_riscv64_angr(self):
        self.run_test("riscv64.angr", signext=True)

    def test_call_xtensa_angr(self):
        self.run_test("xtensa.angr")


class DMATests(ScriptIntegrationTest):
    def run_test(self, arch, signext=False):
        def test_output(number1, number2, res):
            stdout, _ = self.command(f"python3 dma/dma.{arch}.py {number1} {number2}")
            self.assertLineContainsStrings(stdout, hex(res))

        test_output(10, 2, 0x5)

    def test_dma_amd64(self):
        self.run_test("amd64")

    def test_dma_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_dma_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_dma_aarch64(self):
        self.run_test("aarch64")

    def test_dma_aarch64_angr(self):
        self.run_test("aarch64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_dma_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_dma_armel(self):
        self.run_test("armel")

    def test_dma_armel_angr(self):
        self.run_test("armel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_dma_armel_panda(self):
        self.run_test("armel.panda")

    def test_dma_armhf(self):
        self.run_test("armhf")

    def test_dma_armhf_angr(self):
        self.run_test("armhf.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_dma_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_dma_i386(self):
        self.run_test("i386")

    def test_dma_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_dma_i386_panda(self):
        self.run_test("i386.panda")

    def test_dma_mips(self):
        self.run_test("mips")

    def test_dma_mips_angr(self):
        self.run_test("mips.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_dma_mips_panda(self):
        self.run_test("mips.panda")

    def test_dma_mipsel(self):
        self.run_test("mipsel")

    def test_dma_mipsel_angr(self):
        self.run_test("mipsel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_dma_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_dma_mips64_angr(self):
        self.run_test("mips64.angr", signext=True)

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_dma_mips64_panda(self):
        self.run_test("mips64.panda", signext=True)

    def test_dma_mips64el_angr(self):
        self.run_test("mips64el.angr", signext=True)

    def test_dma_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_dma_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_dma_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_dma_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_dma_xtensa_angr(self):
        self.run_test("xtensa.angr")


class SquareTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command(
            "python3 ../examples/basic_harness.py ./square/square.amd64.bin"
        )

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
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
            '"pc": 4099',
            '"color": 2',
            '"use": true',
            '"new": false',
            '"prob": 1.0',
            '"reg_name": "edi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "write-copy-prob",
            '"pc": 4099',
            '"color": 2',
            '"use": false',
            '"new": false',
            '"prob": 1.0',
            '"reg_name": "eax"',
        )

    def run_test(self, arch, signext=False):
        def test_output(number):
            stdout, _ = self.command(f"python3 square/square.{arch}.py {number}")
            res = number**2
            if signext and res & 0xFFFFFFFF80000000 != 0:
                # MIPS64 sign-extends 32-bit ints to use the full 64-bit register.
                res = 0xFFFFFFFF80000000 | res

            self.assertLineContainsStrings(stdout, hex(res))

        test_output(5)
        test_output(1337)
        test_output(65535)

    def test_square_amd64(self):
        self.run_test(arch="amd64")

    def test_square_amd64_angr(self):
        self.run_test(arch="amd64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_square_amd64_panda(self):
        self.run_test(arch="amd64.panda")

    def test_square_aarch64(self):
        self.run_test(arch="aarch64")

    def test_square_aarch64_angr(self):
        self.run_test(arch="aarch64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_square_aarch64_panda(self):
        self.run_test(arch="aarch64.panda")

    def test_square_armel(self):
        self.run_test(arch="armel")

    def test_square_armel_angr(self):
        self.run_test(arch="armel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_square_armel_panda(self):
        self.run_test(arch="armel.panda")

    def test_square_armhf(self):
        self.run_test(arch="armhf")

    def test_square_armhf_angr(self):
        self.run_test(arch="armhf.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_square_armhf_panda(self):
        self.run_test(arch="armhf.panda")

    def test_square_i386(self):
        self.run_test(arch="i386")

    def test_square_i386_angr(self):
        self.run_test(arch="i386.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_square_i386_panda(self):
        self.run_test(arch="i386.panda")

    def test_square_mips(self):
        self.run_test(arch="mips")

    def test_square_mips_angr(self):
        self.run_test(arch="mips.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_square_mips_panda(self):
        self.run_test(arch="mips.panda")

    def test_square_mipsel(self):
        self.run_test(arch="mipsel")

    def test_square_mipsel_angr(self):
        self.run_test(arch="mipsel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_square_mipsel_panda(self):
        self.run_test(arch="mipsel.panda")

    def test_square_mips64_angr(self):
        self.run_test(arch="mips64.angr", signext=True)

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_square_mips64_panda(self):
        self.run_test(arch="mips64.panda", signext=True)

    def test_square_mips64el_angr(self):
        self.run_test(arch="mips64el.angr", signext=True)

    def test_square_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_square_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_square_ppc64_angr(self):
        self.run_test("ppc64.angr", signext=True)

    def test_square_riscv64_angr(self):
        self.run_test("riscv64.angr", signext=True)

    def test_square_xtensa_angr(self):
        self.run_test("xtensa.angr")


class RecursionTests(ScriptIntegrationTest):
    def run_test(self, arch):
        def test_output(number, res):
            stdout, _ = self.command(f"python3 recursion/recursion.{arch}.py {number}")
            self.assertLineContainsStrings(stdout, hex(res))

        test_output(-1, 91)
        test_output(0, 91)
        test_output(100, 91)
        test_output(101, 91)
        test_output(102, 92)

    def test_recursion_amd64(self):
        self.run_test("amd64")

    def test_recursion_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_recursion_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_recursion_aarch64(self):
        self.run_test("aarch64")

    def test_recursion_aarch64_angr(self):
        self.run_test("aarch64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_recursion_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_recursion_armel(self):
        self.run_test("armel")

    def test_recursion_armel_angr(self):
        self.run_test("armel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_recursion_armel_panda(self):
        self.run_test("armel.panda")

    def test_recursion_armhf(self):
        self.run_test("armhf")

    def test_recursion_armhf_angr(self):
        self.run_test("armhf.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_recursion_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_recursion_i386(self):
        self.run_test("i386")

    def test_recursion_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_recursion_i386_panda(self):
        self.run_test("i386.panda")

    def test_recursion_mips(self):
        self.run_test("mips")

    def test_recursion_mips_angr(self):
        self.run_test("mips.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_recursion_mips_panda(self):
        self.run_test("mips.panda")

    def test_recursion_mipsel(self):
        self.run_test("mipsel")

    def test_recursion_mipsel_angr(self):
        self.run_test("mipsel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_recursion_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_recursion_mips64_angr(self):
        self.run_test("mips64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_recursion_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_recursion_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_recursion_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_recursion_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_recursion_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_recursion_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_xtensa_angr(self):
        self.run_test("xtensa.angr")


class BlockTests(ScriptIntegrationTest):
    def run_test(self, arch):
        def test_output():
            stdout, _ = self.command(f"python3 block/block.{arch}.py 2740 1760")
            self.assertLineContainsStrings(stdout, "1", "1760")
            self.assertLineContainsStrings(stdout, "2", "1760")
            self.assertLineContainsStrings(stdout, "3", "0")
            self.assertLineContainsStrings(stdout, "4", "1")
            self.assertLineContainsStrings(stdout, "5", "980")
            self.assertLineContainsStrings(stdout, "6", "20")

        test_output()

    def test_block_amd64(self):
        self.run_test("amd64")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_block_amd64_panda(self):
        self.run_test("amd64.panda")


class StackTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command(
            "python3 ../examples/basic_harness.py stack/stack.amd64.bin"
        )

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
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
            '"pc": 4103',
            '"color": 6',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "rsp"',
        )

        # self.assertLineContainsStrings(stderr, '"pointer"', '"base": "rsp"')

        # self.assertLineContainsStrings(
        #    stderr, '{"4096": 1, "4099": 1, "4103": 1}', "coverage"
        # )

    def run_test(self, arch, reg="eax", res="0xaaaaaaaa"):
        stdout, _ = self.command(f"python3 stack/stack.{arch}.py")
        self.assertLineContainsStrings(stdout, reg, res)

    def test_stack_amd64(self):
        self.run_test("amd64")

    def test_stack_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_stack_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_stack_aarch64(self):
        self.run_test("aarch64", reg="x0", res="0xffffffff")

    def test_stack_aarch64_angr(self):
        self.run_test("aarch64.angr", reg="x0", res="0xffffffff")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_stack_aarch64_panda(self):
        self.run_test("aarch64.panda", reg="x0", res="0xffffffff")

    def test_stack_armel(self):
        self.run_test("armel", reg="r0")

    def test_stack_armel_angr(self):
        self.run_test("armel.angr", reg="r0")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_stack_armel_panda(self):
        self.run_test("armel.panda", reg="r0")

    def test_stack_armhf(self):
        self.run_test("armhf", reg="r0")

    def test_stack_armhf_angr(self):
        self.run_test("armhf.angr", reg="r0")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_stack_armhf_panda(self):
        self.run_test("armhf.panda", reg="r0")

    def test_stack_i386(self):
        self.run_test("i386")

    def test_stack_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_stack_i386_panda(self):
        self.run_test("i386.panda")

    def test_stack_mips(self):
        self.run_test("mips", reg="v0", res="0xaaaa")

    def test_stack_mips_angr(self):
        self.run_test("mips.angr", reg="v0", res="0xaaaa")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_stack_mips_panda(self):
        self.run_test("mips.panda", reg="v0", res="0xaaaa")

    def test_stack_mipsel(self):
        self.run_test("mipsel", reg="v0", res="0xaaaa")

    def test_stack_mipsel_angr(self):
        self.run_test("mipsel.angr", reg="v0", res="0xaaaa")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_stack_mipsel_panda(self):
        self.run_test("mipsel.panda", reg="v0", res="0xaaaa")

    def test_stack_mips64_angr(self):
        self.run_test("mips64.angr", reg="v0", res="0xffff")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_stack_mips64_panda(self):
        self.run_test("mips64.panda", reg="v0", res="0xffff")

    def test_stack_mips64el_angr(self):
        self.run_test("mips64el.angr", reg="v0", res="0xffff")

    def test_stack_ppc_angr(self):
        self.run_test("ppc.angr", reg="r3", res="0xffff")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_stack_ppc_panda(self):
        self.run_test("ppc.panda", reg="r3", res="0xffff")

    def test_stack_ppc64_angr(self):
        self.run_test("ppc64.angr", reg="r3", res="0xffff")

    def test_stack_riscv64_angr(self):
        self.run_test("riscv64.angr", reg="a0", res="0xffffffff")

    def test_stack_xtensa(self):
        self.run_test("xtensa.angr", reg="a2", res="0xaaaaaaaa")


class StructureTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command(
            "python3 ../examples/basic_harness.py struct/struct.amd64.bin"
        )

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
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
            '"pc": 4113',
            '"prob": 1.0',
            '"is_read": true',
            '"base_reg_name": "rdi"',
            '"index_reg_name": "None"',
            '"offset": 24',
            '"scale": 1',
        )

        # self.assertLineContainsStrings(
        #    stderr, "from_instruction", "6w8=", "4096", "to_instruction", "i0cY", "4113"
        # )
        # self.assertLineContainsStrings(stderr, '{"4096": 1, "4113": 1}', "coverage")
        # self.assertLineContainsStrings(stderr, "address", "4113", "code_reachable")
        # self.assertLineContainsStrings(stderr, "address", "4098", "code_reachable")
        # self.assertLineContainsStrings(stderr, "address", "4120", "code_reachable")


class BranchTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command(
            "python3 ../examples/basic_harness.py branch/branch.amd64.bin"
        )

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueProbHint",
            "read-def-prob",
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
            '"pc": 4098',
            '"color": 2',
            '"use": true',
            '"new": true',
            '"prob": 1.0',
            '"reg_name": "rdi"',
        )
        # self.assertLineContainsStrings(
        #    stderr, '{"4096": 1, "4098": 1, "4102": 1}', "coverage"
        # )

    def run_branch(self, arch, reg="eax"):
        stdout, _ = self.command(f"python3 branch/branch.{arch}.py 99")
        self.assertLineContainsStrings(stdout, reg, "0x0")

        stdout, _ = self.command(f"python3 branch/branch.{arch}.py 100")
        self.assertLineContainsStrings(stdout, reg, "0x1")

        stdout, _ = self.command(f"python3 branch/branch.{arch}.py 101")
        self.assertLineContainsStrings(stdout, reg, "0x0")

    def test_branch_amd64(self):
        self.run_branch("amd64")

    def test_branch_amd64_angr(self):
        self.run_branch("amd64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_branch_amd64_panda(self):
        self.run_branch("amd64.panda")

    def test_branch_aarch64(self):
        self.run_branch("aarch64", reg="w0")

    def test_branch_aarch64_angr(self):
        self.run_branch("aarch64.angr", reg="w0")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_branch_aarch64_panda(self):
        self.run_branch("aarch64.panda", reg="w0")

    def test_branch_armel(self):
        self.run_branch("armel", reg="r0")

    def test_branch_armel_angr(self):
        self.run_branch("armel.angr", reg="r0")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_branch_armel_panda(self):
        self.run_branch("armel.panda", reg="r0")

    def test_branch_armhf(self):
        self.run_branch("armhf", reg="r0")

    def test_branch_armhf_angr(self):
        self.run_branch("armhf.angr", reg="r0")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_branch_armhf_panda(self):
        self.run_branch("armhf.panda", reg="r0")

    def test_branch_i386(self):
        self.run_branch("i386")

    def test_branch_i386_angr(self):
        self.run_branch("i386.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_branch_i386_panda(self):
        self.run_branch("i386.panda")

    def test_branch_mips(self):
        self.run_branch("mips", reg="v0")

    def test_branch_mips_angr(self):
        self.run_branch("mips.angr", reg="v0")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_branch_mips_panda(self):
        self.run_branch("mips.panda", reg="v0")

    def test_branch_mipsel(self):
        self.run_branch("mipsel", reg="v0")

    def test_branch_mipsel_angr(self):
        self.run_branch("mipsel.angr", reg="v0")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_branch_mipsel_panda(self):
        self.run_branch("mipsel.panda", reg="v0")

    def test_branch_mips64_angr(self):
        self.run_branch("mips64.angr", reg="v0")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_branch_mips64_panda(self):
        self.run_branch("mips64.panda", reg="v0")

    def test_branch_mips64el_angr(self):
        self.run_branch("mips64el.angr", reg="v0")

    def test_branch_ppc_angr(self):
        self.run_branch("ppc.angr", reg="r3")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_branch_ppc_panda(self):
        self.run_branch("ppc.panda", reg="r3")

    def test_branch_ppc64_angr(self):
        self.run_branch("ppc64.angr", reg="r3")

    def test_branch_riscv64_angr(self):
        self.run_branch("riscv64.angr", reg="a0")

    def test_branch_xtensa_angr(self):
        self.run_branch("xtensa.angr", reg="a2")


class StrlenTests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 strlen/strlen.{arch}.py ''")
        self.assertLineContainsStrings(stdout, "0x0")

        stdout, _ = self.command(f"python3 strlen/strlen.{arch}.py foobar")
        self.assertLineContainsStrings(stdout, "0x6")

    def test_strlen_amd64(self):
        self.run_test("amd64")

    def test_strlen_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_strlen_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_strlen_aarch64(self):
        self.run_test("aarch64")

    def test_strlen_aarch64_angr(self):
        self.run_test("aarch64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_strlen_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_strlen_armel(self):
        self.run_test("armel")

    def test_strlen_armel_angr(self):
        self.run_test("armel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_strlen_armel_panda(self):
        self.run_test("armel.panda")

    def test_strlen_armhf(self):
        self.run_test("armhf")

    def test_strlen_armhf_angr(self):
        self.run_test("armhf.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_strlen_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_strlen_i386(self):
        self.run_test("i386")

    def test_strlen_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_strlen_i386_panda(self):
        self.run_test("i386.panda")

    def test_strlen_mips(self):
        self.run_test("mips")

    def test_strlen_mips_angr(self):
        self.run_test("mips.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_strlen_mips_panda(self):
        self.run_test("mips.panda")

    def test_strlen_mipsel(self):
        self.run_test("mipsel")

    def test_strlen_mipsel_angr(self):
        self.run_test("mipsel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_strlen_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_strlen_mips64_angr(self):
        self.run_test("mips64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_strlen_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_strlen_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_strlen_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_strlen_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_strlen_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_strlen_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_strlen_xtensa_angr(self):
        self.run_test("xtensa.angr")


class HookingTests(ScriptIntegrationTest):
    def run_test(self, arch, heckingMIPS64=False):
        if heckingMIPS64:
            # FIXME: Running hooking.mips64.panda.py IN THE INTEGRATION TESTS fails.
            # It's fine run on its own.  No idea what's up
            expected = "oo bar baz"
        else:
            expected = "foo bar baz"
        stdout, _ = self.command(
            f"python3 hooking/hooking.{arch}.py", stdin="foo bar baz"
        )
        self.assertLineContainsStrings(stdout, expected)

    def test_hooking_amd64(self):
        self.run_test("amd64")

    def test_hooking_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_hooking_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_hooking_aarch64(self):
        self.run_test("aarch64")

    def test_hooking_aarch64_angr(self):
        self.run_test("aarch64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_hooking_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_hooking_armel(self):
        self.run_test("armel")

    def test_hooking_armel_angr(self):
        self.run_test("armel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_hooking_armel_panda(self):
        self.run_test("armel.panda")

    def test_hooking_armhf(self):
        self.run_test("armhf")

    def test_hooking_armhf_angr(self):
        self.run_test("armhf.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_hooking_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_hooking_i386(self):
        self.run_test("i386")

    def test_hooking_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_hooking_i386_panda(self):
        self.run_test("i386.panda")

    def test_hooking_mips(self):
        self.run_test("mips")

    def test_hooking_mips_angr(self):
        self.run_test("mips.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_hooking_mips_panda(self):
        self.run_test("mips.panda")

    def test_hooking_mipsel(self):
        self.run_test("mipsel")

    def test_hooking_mipsel_angr(self):
        self.run_test("mipsel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_hooking_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_hooking_mips64_angr(self):
        self.run_test("mips64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_hooking_mips64_panda(self):
        # There is a crazy bug in panda/mips64;
        # it forgets the first character
        self.run_test("mips64.panda", heckingMIPS64=True)

    def test_hooking_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_hooking_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_hooking_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_hooking_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_hooking_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_hooking_xtensa_angr(self):
        self.run_test("xtensa.angr")


class ElfTests(ScriptIntegrationTest):
    def run_test(self, arch):
        self.command(f"python3 elf/elf.{arch}.py foobar")

    def test_elf_aarch64(self):
        self.run_test("aarch64")

    def test_elf_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_elf_amd64(self):
        self.run_test("amd64")

    def test_elf_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_elf_armel(self):
        self.run_test("armel")

    def test_elf_armel_angr(self):
        self.run_test("armel.angr")

    def test_elf_armhf(self):
        self.run_test("armhf")

    def test_elf_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_elf_i386(self):
        self.run_test("i386")

    def test_elf_i386_angr(self):
        self.run_test("i386.angr")

    def test_elf_mips(self):
        self.run_test("mips")

    def test_elf_mips_angr(self):
        self.run_test("mips.angr")

    def test_elf_mipsel(self):
        self.run_test("mipsel")

    def test_elf_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_elf_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_elf_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_elf_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_elf_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_elf_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_elf_xtensa_angr(self):
        self.run_test("xtensa.angr")


class RelaTests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 rela/rela.{arch}.py")
        self.assertLineContainsStrings(stdout, "Hello, world!")

    def test_rela_amd64(self):
        self.run_test("amd64")

    def test_rela_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_rela_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_rela_aarch64(self):
        self.run_test("aarch64")

    def test_rela_aarch64_angr(self):
        self.run_test("aarch64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_rela_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_rela_armel(self):
        self.run_test("armel")

    def test_rela_armel_angr(self):
        self.run_test("armel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_rela_armel_panda(self):
        self.run_test("armel.panda")

    def test_rela_armhf(self):
        self.run_test("armhf")

    def test_rela_armhf_angr(self):
        self.run_test("armhf.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_rela_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_rela_i386(self):
        self.run_test("i386")

    def test_rela_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_rela_i386_panda(self):
        self.run_test("i386.panda")

    def test_rela_mips(self):
        self.run_test("mips")

    def test_rela_mips_angr(self):
        self.run_test("mips.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_rela_mips_panda(self):
        self.run_test("mips.panda")

    def test_rela_mipsel(self):
        self.run_test("mipsel")

    def test_rela_mipsel_angr(self):
        self.run_test("mipsel.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_rela_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_rela_mips64_angr(self):
        self.run_test("mips64.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_rela_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_rela_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_rela_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skipUnless(pandare, "Panda support is optional")
    def test_rela_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_rela_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_rela_riscv64_angr(self):
        self.run_test("riscv64.angr")

    # NOTE: xtensa doesn't have a glibc, so this test doesn't do.


class FloatsTests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 floats/floats.{arch}.py 2.2 1.1")
        self.assertLineContainsStrings("3.3")

    def test_floats_aarch64(self):
        self.run_test("aarch64")

    def test_floats_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_floats_amd64(self):
        self.run_test("amd64")

    def test_floats_amd64_angr(self):
        self.run_test("amd64.angr")

    # NOTE: armel has no FPU, so no tests

    # NOTE: Unicorn does not support armhf float instructions

    def test_floats_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_floats_i386(self):
        self.run_test("i386")

    def test_floats_i386_angr(self):
        self.run_test("i386.angr")

    # NOTE: mips be crazy

    # NOTE: No idea about PPC

    # NOTE: I can't get the assembler to build riscv64 FPU code

    # NOTE: xtensa has no FPU, so no tests


class SyscallTests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 syscall/syscall.{arch}.py")
        self.assertLineContainsStrings("Executing syscall")
        self.assertLineContainsStrings("Executing a write syscall")

    def test_syscall_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_syscall_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_syscall_armel_angr(self):
        self.run_test("armel.angr")

    def test_syscall_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_syscall_i386_angr(self):
        self.run_test("i386.angr")

    def test_syscall_mips_angr(self):
        self.run_test("mips.angr")

    def test_syscall_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_syscall_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_syscall_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_syscall_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_syscall_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_syscall_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_syscall_xtensa_angr(self):
        self.run_test("xtensa.angr")


class FuzzTests(ScriptIntegrationTest):
    def run_fuzz(self, arch: str):
        stdout, _ = self.command(f"python3 fuzz/fuzz.{arch}.py")
        self.assertLineContainsStrings(stdout, "=0x0")

        _, stderr = self.command(f"python3 fuzz/fuzz.{arch}.py -c")
        self.assertLineContainsStrings(stderr, "UC_ERR_WRITE_UNMAPPED")

        # TODO panda on bad input doesnt fail atm

    def run_afl(self, arch: str, lines):
        stdout, _ = self.command(
            f"afl-showmap -t 10000 -U -m none -o /dev/stdout -- python3 fuzz/afl_fuzz.{arch}.py fuzz/fuzz_inputs/good_input",
            error=False,
        )
        for line in lines:
            self.assertLineContainsStrings(stdout, line)

    def test_fuzz_amd64(self):
        self.run_fuzz("amd64")

    @unittest.skipUnless(unicornafl, "afl++ must be installed from source")
    def test_afl_amd64(self):
        self.run_afl(
            "amd64",
            [
                "001445:1",
                "003349:1",
                "014723:1",
                "032232:1",
                "032233:1",
                "032234:1",
                "040896:1",
            ],
        )

    def test_fuzz_aarch64(self):
        self.run_fuzz("aarch64")

    @unittest.skipUnless(unicornafl, "afl++ must be installed from source")
    def test_afl_aarch64(self):
        self.run_afl(
            "aarch64",
            [
                "002975:1",
                "022192:1",
                "039638:1",
                "050871:1",
            ],
        )

    def test_fuzz_armel(self):
        self.run_fuzz("armel")

    @unittest.skipUnless(unicornafl, "afl++ must be installed from source")
    def test_afl_armel(self):
        self.run_afl(
            "armel",
            [
                "002975:1",
                "022192:1",
                "050871:1",
            ],
        )

    def test_fuzz_armhf(self):
        self.run_fuzz("armhf")

    @unittest.skipUnless(unicornafl, "afl++ must be installed from source")
    def test_afl_armhf(self):
        self.run_afl(
            "armhf",
            [
                "002975:1",
                "022192:1",
                "050871:1",
            ],
        )

    def test_fuzz_mips(self):
        self.run_fuzz("mips")

    @unittest.skipUnless(unicornafl, "afl++ must be installed from source")
    def test_afl_mips(self):
        self.run_afl(
            "mips",
            [
                "013057:1",
                "022192:1",
                "036571:1",
                "052670:1",
            ],
        )

    def test_fuzz_mipsel(self):
        self.run_fuzz("mipsel")

    @unittest.skipUnless(unicornafl, "afl++ must be installed from source")
    def test_afl_mipsel(self):
        self.run_afl(
            "mipsel",
            [
                "013057:1",
                "022192:1",
                "036571:1",
                "052670:1",
            ],
        )


class SymbolicTests(ScriptIntegrationTest):
    # NOTE: I made symbolic tests self-contained; they'll error on failure
    def test_branch_symbolic(self):
        self.command("python3 symbolic/branch.amd64.angr.symbolic.py")

    def test_dma_symbolic(self):
        self.command("python3 symbolic/dma.amd64.angr.symbolic.py 10 2")

    def test_hooking_symbolic(self):
        self.command(
            "python3 symbolic/hooking.amd64.angr.symbolic.py", stdin="foo bar baz"
        )

    def test_square_symbolic(self):
        self.command("python3 symbolic/square.amd64.angr.symbolic.py")


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
