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

    def test_call_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_call_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_call_aarch64(self):
        self.run_test("aarch64")

    def test_call_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_call_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_call_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_call_armel(self):
        self.run_test("armel")

    def test_call_armel_angr(self):
        self.run_test("armel.angr")

    def test_call_armel_panda(self):
        self.run_test("armel.panda")

    def test_call_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_call_armhf(self):
        self.run_test("armhf")

    def test_call_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_call_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_call_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_call_i386(self):
        self.run_test("i386")

    def test_call_i386_angr(self):
        self.run_test("i386.angr")

    def test_call_i386_panda(self):
        self.run_test("i386.panda")

    def test_call_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_call_mips(self):
        self.run_test("mips")

    def test_call_mips_angr(self):
        self.run_test("mips.angr")

    def test_call_mips_panda(self):
        self.run_test("mips.panda")

    def test_call_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_call_mipsel(self):
        self.run_test("mipsel")

    def test_call_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_call_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_call_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_call_mips64_angr(self):
        self.run_test("mips64.angr", signext=True)

    def test_call_mips64_panda(self):
        self.run_test("mips64.panda", signext=True)

    def test_call_mips64_pcode(self):
        self.run_test("mips64.pcode", signext=True)

    def test_call_mips64el_angr(self):
        self.run_test("mips64el.angr", signext=True)

    def test_call_mips64el_panda(self):
        self.run_test("mips64el.panda", signext=True)

    def test_call_mips64el_pcode(self):
        self.run_test("mips64el.pcode", signext=True)

    def test_call_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_call_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_call_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_call_ppc64_angr(self):
        self.run_test("ppc64.angr", signext=True)

    def test_call_ppc64_pcode(self):
        self.run_test("ppc64.pcode", signext=True)

    def test_call_riscv64_angr(self):
        self.run_test("riscv64.angr", signext=True)

    def test_call_riscv64_pcode(self):
        self.run_test("riscv64.pcode", signext=True)

    def test_call_xtensa_angr(self):
        self.run_test("xtensa.angr")

    def test_call_xtensa_pcode(self):
        self.run_test("xtensa.pcode")


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

    def test_dma_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_dma_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_dma_aarch64(self):
        self.run_test("aarch64")

    def test_dma_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_dma_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_dma_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_dma_armel(self):
        self.run_test("armel")

    def test_dma_armel_angr(self):
        self.run_test("armel.angr")

    def test_dma_armel_panda(self):
        self.run_test("armel.panda")

    def test_dma_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_dma_armhf(self):
        self.run_test("armhf")

    def test_dma_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_dma_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_dma_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_dma_i386(self):
        self.run_test("i386")

    def test_dma_i386_angr(self):
        self.run_test("i386.angr")

    def test_dma_i386_panda(self):
        self.run_test("i386.panda")

    def test_dma_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_dma_mips(self):
        self.run_test("mips")

    def test_dma_mips_angr(self):
        self.run_test("mips.angr")

    def test_dma_mips_panda(self):
        self.run_test("mips.panda")

    def test_dma_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_dma_mipsel(self):
        self.run_test("mipsel")

    def test_dma_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_dma_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_dma_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_dma_mips64_angr(self):
        self.run_test("mips64.angr", signext=True)

    def test_dma_mips64_panda(self):
        self.run_test("mips64.panda", signext=True)

    def test_dma_mips64_pcode(self):
        self.run_test("mips64.pcode", signext=True)

    def test_dma_mips64el_angr(self):
        self.run_test("mips64el.angr", signext=True)

    def test_dma_mips64el_panda(self):
        self.run_test("mips64el.panda", signext=True)

    def test_dma_mips64el_pcode(self):
        self.run_test("mips64el.pcode", signext=True)

    def test_dma_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_dma_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_dma_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_dma_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_dma_ppc64_pcode(self):
        self.run_test("ppc64.pcode")

    def test_dma_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_dma_riscv64_pcode(self):
        self.run_test("riscv64.pcode")

    def test_dma_xtensa_angr(self):
        self.run_test("xtensa.angr")

    def test_dma_xtensa_pcode(self):
        self.run_test("xtensa.pcode")


class SquareTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command(
            "python3 ../examples/basic_harness.py ./square/square.amd64.bin"
        )

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-def-summary",
            '"pc": 4096',
            '"color": 1',
            '"use": true',
            '"new": true',
            '"count": 10',
            '"reg_name": "edi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "write-def-summary",
            '"pc": 4096',
            '"color": 2',
            '"use": false',
            '"new": true',
            '"count": 10',
            '"reg_name": "edi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-flow-summary",
            '"pc": 4099',
            '"color": 2',
            '"use": true',
            '"new": false',
            '"count": 10',
            '"reg_name": "edi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "write-copy-summary",
            '"pc": 4099',
            '"color": 2',
            '"use": false',
            '"new": false',
            '"count": 10',
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

    def test_square_amd64_panda(self):
        self.run_test(arch="amd64.panda")

    def test_square_amd64_pcode(self):
        self.run_test(arch="amd64.pcode")

    def test_square_aarch64(self):
        self.run_test(arch="aarch64")

    def test_square_aarch64_angr(self):
        self.run_test(arch="aarch64.angr")

    def test_square_aarch64_panda(self):
        self.run_test(arch="aarch64.panda")

    def test_square_aarch64_pcode(self):
        self.run_test(arch="aarch64.pcode")

    def test_square_armel(self):
        self.run_test(arch="armel")

    def test_square_armel_angr(self):
        self.run_test(arch="armel.angr")

    def test_square_armel_panda(self):
        self.run_test(arch="armel.panda")

    def test_square_armel_pcode(self):
        self.run_test(arch="armel.pcode")

    def test_square_armhf(self):
        self.run_test(arch="armhf")

    def test_square_armhf_angr(self):
        self.run_test(arch="armhf.angr")

    def test_square_armhf_panda(self):
        self.run_test(arch="armhf.panda")

    def test_square_armhf_pcode(self):
        self.run_test(arch="armhf.pcode")

    def test_square_i386(self):
        self.run_test(arch="i386")

    def test_square_i386_angr(self):
        self.run_test(arch="i386.angr")

    def test_square_i386_panda(self):
        self.run_test(arch="i386.panda")

    def test_square_i386_pcode(self):
        self.run_test(arch="i386.pcode")

    def test_square_mips(self):
        self.run_test(arch="mips")

    def test_square_mips_angr(self):
        self.run_test(arch="mips.angr")

    def test_square_mips_panda(self):
        self.run_test(arch="mips.panda")

    def test_square_mips_pcode(self):
        self.run_test(arch="mips.pcode")

    def test_square_mipsel(self):
        self.run_test(arch="mipsel")

    def test_square_mipsel_angr(self):
        self.run_test(arch="mipsel.angr")

    def test_square_mipsel_panda(self):
        self.run_test(arch="mipsel.panda")

    def test_square_mipsel_pcode(self):
        self.run_test(arch="mipsel.pcode")

    def test_square_mips64_angr(self):
        self.run_test(arch="mips64.angr", signext=True)

    def test_square_mips64_panda(self):
        self.run_test(arch="mips64.panda", signext=True)

    def test_square_mips64_pcode(self):
        self.run_test(arch="mips64.pcode", signext=True)

    def test_square_mips64el_angr(self):
        self.run_test(arch="mips64el.angr", signext=True)

    def test_square_mips64el_panda(self):
        self.run_test(arch="mips64el.panda", signext=True)

    def test_square_mips64el_pcode(self):
        self.run_test(arch="mips64el.pcode", signext=True)

    def test_square_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_square_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_square_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_square_ppc64_angr(self):
        self.run_test("ppc64.angr", signext=True)

    def test_square_ppc64_pcode(self):
        self.run_test("ppc64.pcode", signext=True)

    def test_square_riscv64_angr(self):
        self.run_test("riscv64.angr", signext=True)

    def test_square_riscv64_pcode(self):
        self.run_test("riscv64.pcode", signext=True)

    def test_square_xtensa_angr(self):
        self.run_test("xtensa.angr")

    def test_square_xtensa_pcode(self):
        self.run_test("xtensa.pcode")


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

    def test_recursion_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_recursion_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_recursion_aarch64(self):
        self.run_test("aarch64")

    def test_recursion_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_recursion_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_recursion_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_recursion_armel(self):
        self.run_test("armel")

    def test_recursion_armel_angr(self):
        self.run_test("armel.angr")

    def test_recursion_armel_panda(self):
        self.run_test("armel.panda")

    def test_recursion_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_recursion_armhf(self):
        self.run_test("armhf")

    def test_recursion_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_recursion_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_recursion_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_recursion_i386(self):
        self.run_test("i386")

    def test_recursion_i386_angr(self):
        self.run_test("i386.angr")

    def test_recursion_i386_panda(self):
        self.run_test("i386.panda")

    def test_recursion_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_recursion_mips(self):
        self.run_test("mips")

    def test_recursion_mips_angr(self):
        self.run_test("mips.angr")

    def test_recursion_mips_panda(self):
        self.run_test("mips.panda")

    def test_recursion_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_recursion_mipsel(self):
        self.run_test("mipsel")

    def test_recursion_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_recursion_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_recursion_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_recursion_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_recursion_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_recursion_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_recursion_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_recursion_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_recursion_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_recursion_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_recursion_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_recursion_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_recursion_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_recursion_ppc64_pcode(self):
        self.run_test("ppc64.pcode")

    def test_recursion_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_recursion_riscv64_pcode(self):
        self.run_test("riscv64.pcode")

    def test_xtensa_angr(self):
        self.run_test("xtensa.angr")

    def test_xtensa_pcode(self):
        self.run_test("xtensa.pcode")


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

    def test_block_amd64_panda(self):
        self.run_test("amd64.panda")


class StackTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command(
            "python3 ../examples/basic_harness.py stack/stack.amd64.bin"
        )

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-def-summary",
            '"pc": 4096',
            '"color": 1',
            '"use": true',
            '"new": true',
            '"count": 10',
            '"reg_name": "rdi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-def-summary",
            '"pc": 4096',
            '"color": 2',
            '"use": true',
            '"new": true',
            '"count": 10',
            '"reg_name": "rdx"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "write-def-summary",
            '"pc": 4096',
            '"color": 3',
            '"use": false',
            '"new": true',
            '"count": 10',
            '"reg_name": "rdi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-flow-summary",
            '"pc": 4099',
            '"color": 3',
            '"use": true',
            '"new": false',
            '"count": 10',
            '"reg_name": "rdi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-def-summary",
            '"pc": 4099',
            '"color": 4',
            '"use": true',
            '"new": true',
            '"count": 10',
            '"reg_name": "r8"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "write-def-summary",
            '"pc": 4099',
            '"color": 5',
            '"use": false',
            '"new": true',
            '"count": 10',
            '"reg_name": "rax"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-flow-summary",
            '"pc": 4103',
            '"color": 5',
            '"use": true',
            '"new": false',
            '"count": 10',
            '"reg_name": "rax"',
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

    def test_stack_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_stack_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_stack_aarch64(self):
        self.run_test("aarch64", reg="x0", res="0xffffffff")

    def test_stack_aarch64_angr(self):
        self.run_test("aarch64.angr", reg="x0", res="0xffffffff")

    def test_stack_aarch64_panda(self):
        self.run_test("aarch64.panda", reg="x0", res="0xffffffff")

    def test_stack_aarch64_pcode(self):
        self.run_test("aarch64.pcode", reg="x0", res="0xffffffff")

    def test_stack_armel(self):
        self.run_test("armel", reg="r0")

    def test_stack_armel_angr(self):
        self.run_test("armel.angr", reg="r0")

    def test_stack_armel_panda(self):
        self.run_test("armel.panda", reg="r0")

    def test_stack_armel_pcode(self):
        self.run_test("armel.pcode", reg="r0")

    def test_stack_armhf(self):
        self.run_test("armhf", reg="r0")

    def test_stack_armhf_angr(self):
        self.run_test("armhf.angr", reg="r0")

    def test_stack_armhf_panda(self):
        self.run_test("armhf.panda", reg="r0")

    def test_stack_armhf_pcode(self):
        self.run_test("armhf.pcode", reg="r0")

    def test_stack_i386(self):
        self.run_test("i386")

    def test_stack_i386_angr(self):
        self.run_test("i386.angr")

    def test_stack_i386_panda(self):
        self.run_test("i386.panda")

    def test_stack_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_stack_mips(self):
        self.run_test("mips", reg="v0", res="0xaaaa")

    def test_stack_mips_angr(self):
        self.run_test("mips.angr", reg="v0", res="0xaaaa")

    def test_stack_mips_panda(self):
        self.run_test("mips.panda", reg="v0", res="0xaaaa")

    def test_stack_mips_pcode(self):
        self.run_test("mips.pcode", reg="v0", res="0xaaaa")

    def test_stack_mipsel(self):
        self.run_test("mipsel", reg="v0", res="0xaaaa")

    def test_stack_mipsel_angr(self):
        self.run_test("mipsel.angr", reg="v0", res="0xaaaa")

    def test_stack_mipsel_panda(self):
        self.run_test("mipsel.panda", reg="v0", res="0xaaaa")

    def test_stack_mipsel_pcode(self):
        self.run_test("mipsel.pcode", reg="v0", res="0xaaaa")

    def test_stack_mips64_angr(self):
        self.run_test("mips64.angr", reg="v0", res="0xffff")

    def test_stack_mips64_panda(self):
        self.run_test("mips64.panda", reg="v0", res="0xffff")

    def test_stack_mips64_pcode(self):
        self.run_test("mips64.pcode", reg="v0", res="0xffff")

    def test_stack_mips64el_angr(self):
        self.run_test("mips64el.angr", reg="v0", res="0xffff")

    def test_stack_mips64el_panda(self):
        self.run_test("mips64el.panda", reg="v0", res="0xffff")

    def test_stack_mips64el_pcode(self):
        self.run_test("mips64el.pcode", reg="v0", res="0xffff")

    def test_stack_ppc_angr(self):
        self.run_test("ppc.angr", reg="r3", res="0xffff")

    def test_stack_ppc_panda(self):
        self.run_test("ppc.panda", reg="r3", res="0xffff")

    def test_stack_ppc_pcode(self):
        self.run_test("ppc.pcode", reg="r3", res="0xffff")

    def test_stack_ppc64_angr(self):
        self.run_test("ppc64.angr", reg="r3", res="0xffff")

    def test_stack_ppc64_pcode(self):
        self.run_test("ppc64.pcode", reg="r3", res="0xffff")

    def test_stack_riscv64_angr(self):
        self.run_test("riscv64.angr", reg="a0", res="0xffffffff")

    def test_stack_riscv64_pcode(self):
        self.run_test("riscv64.pcode", reg="a0", res="0xffffffff")

    def test_stack_xtensa_angr(self):
        self.run_test("xtensa.angr", reg="a2", res="0xaaaaaaaa")

    def test_stack_xtensa_pcode(self):
        self.run_test("xtensa.pcode", reg="a2", res="0xaaaaaaaa")


class StructureTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command(
            "python3 ../examples/basic_harness.py struct/struct.amd64.bin"
        )

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-def-summary",
            '"pc": 4113',
            '"color": 1',
            '"use": true',
            '"new": true',
            '"count": 10',
            '"reg_name": "rdi"',
        )
        self.assertLineContainsStrings(
            stderr,
            "MemoryUnavailableSummaryHint",
            "mem_unavailable-summary",
            '"pc": 4113',
            '"count": 10',
            '"is_read": true',
            '"base_reg_name": "rdi"',
            '"index_reg_name": "None"',
            '"offset": 24',
            '"scale": 1',
        )

    def test_unicorn(self):
        stdout, _ = self.command("python3 struct/struct.amd64.py")
        self.assertLineContainsStrings(stdout, "arg2 = 42")

    def test_panda(self):
        stdout, _ = self.command("python3 struct/struct.amd64.panda.py")
        self.assertLineContainsStrings(stdout, "arg2 = 42")


class BranchTests(ScriptIntegrationTest):
    def test_basic(self):
        _, stderr = self.command(
            "python3 ../examples/basic_harness.py branch/branch.amd64.bin"
        )

        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-def-summary",
            '"pc": 4096',
            '"color": 1',
            '"use": true',
            '"new": true',
            '"count": 10',
            '"reg_name": "eax"',
        )
        self.assertLineContainsStrings(
            stderr,
            "DynamicRegisterValueSummaryHint",
            "read-def-summary",
            '"pc": 4098',
            '"color": 2',
            '"use": true',
            '"new": true',
            '"count": 10',
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

    def test_branch_amd64_panda(self):
        self.run_branch("amd64.panda")

    def test_branch_amd64_pcode(self):
        self.run_branch("amd64.pcode")

    def test_branch_aarch64(self):
        self.run_branch("aarch64", reg="w0")

    def test_branch_aarch64_angr(self):
        self.run_branch("aarch64.angr", reg="w0")

    def test_branch_aarch64_panda(self):
        self.run_branch("aarch64.panda", reg="w0")

    def test_branch_aarch64_pcode(self):
        self.run_branch("aarch64.pcode", reg="w0")

    def test_branch_armel(self):
        self.run_branch("armel", reg="r0")

    def test_branch_armel_angr(self):
        self.run_branch("armel.angr", reg="r0")

    def test_branch_armel_panda(self):
        self.run_branch("armel.panda", reg="r0")

    def test_branch_armel_pcode(self):
        self.run_branch("armel.pcode", reg="r0")

    def test_branch_armhf(self):
        self.run_branch("armhf", reg="r0")

    def test_branch_armhf_angr(self):
        self.run_branch("armhf.angr", reg="r0")

    def test_branch_armhf_panda(self):
        self.run_branch("armhf.panda", reg="r0")

    def test_branch_armhf_pcode(self):
        self.run_branch("armhf.pcode", reg="r0")

    def test_branch_i386(self):
        self.run_branch("i386")

    def test_branch_i386_angr(self):
        self.run_branch("i386.angr")

    def test_branch_i386_panda(self):
        self.run_branch("i386.panda")

    def test_branch_i386_pcode(self):
        self.run_branch("i386.pcode")

    def test_branch_mips(self):
        self.run_branch("mips", reg="v0")

    def test_branch_mips_angr(self):
        self.run_branch("mips.angr", reg="v0")

    def test_branch_mips_panda(self):
        self.run_branch("mips.panda", reg="v0")

    def test_branch_mips_pcode(self):
        self.run_branch("mips.pcode", reg="v0")

    def test_branch_mipsel(self):
        self.run_branch("mipsel", reg="v0")

    def test_branch_mipsel_angr(self):
        self.run_branch("mipsel.angr", reg="v0")

    def test_branch_mipsel_panda(self):
        self.run_branch("mipsel.panda", reg="v0")

    def test_branch_mipsel_pcode(self):
        self.run_branch("mipsel.pcode", reg="v0")

    def test_branch_mips64_angr(self):
        self.run_branch("mips64.angr", reg="v0")

    def test_branch_mips64_panda(self):
        self.run_branch("mips64.panda", reg="v0")

    def test_branch_mips64_pcode(self):
        self.run_branch("mips64.pcode", reg="v0")

    def test_branch_mips64el_angr(self):
        self.run_branch("mips64el.angr", reg="v0")

    def test_branch_mips64el_panda(self):
        self.run_branch("mips64el.panda", reg="v0")

    def test_branch_mips64el_pcode(self):
        self.run_branch("mips64el.pcode", reg="v0")

    def test_branch_ppc_angr(self):
        self.run_branch("ppc.angr", reg="r3")

    def test_branch_ppc_panda(self):
        self.run_branch("ppc.panda", reg="r3")

    def test_branch_ppc_pcode(self):
        self.run_branch("ppc.pcode", reg="r3")

    def test_branch_ppc64_angr(self):
        self.run_branch("ppc64.angr", reg="r3")

    def test_branch_ppc64_pcode(self):
        self.run_branch("ppc64.pcode", reg="r3")

    def test_branch_riscv64_angr(self):
        self.run_branch("riscv64.angr", reg="a0")

    def test_branch_riscv64_pcode(self):
        self.run_branch("riscv64.pcode", reg="a0")

    def test_branch_xtensa_angr(self):
        self.run_branch("xtensa.angr", reg="a2")

    def test_branch_xtensa_pcode(self):
        self.run_branch("xtensa.pcode", reg="a2")


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

    def test_strlen_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_strlen_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_strlen_aarch64(self):
        self.run_test("aarch64")

    def test_strlen_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_strlen_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_strlen_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_strlen_armel(self):
        self.run_test("armel")

    def test_strlen_armel_angr(self):
        self.run_test("armel.angr")

    def test_strlen_armel_panda(self):
        self.run_test("armel.panda")

    def test_strlen_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_strlen_armhf(self):
        self.run_test("armhf")

    def test_strlen_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_strlen_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_strlen_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_strlen_i386(self):
        self.run_test("i386")

    def test_strlen_i386_angr(self):
        self.run_test("i386.angr")

    def test_strlen_i386_panda(self):
        self.run_test("i386.panda")

    def test_strlen_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_strlen_mips(self):
        self.run_test("mips")

    def test_strlen_mips_angr(self):
        self.run_test("mips.angr")

    def test_strlen_mips_panda(self):
        self.run_test("mips.panda")

    def test_strlen_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_strlen_mipsel(self):
        self.run_test("mipsel")

    def test_strlen_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_strlen_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_strlen_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_strlen_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_strlen_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_strlen_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_strlen_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_strlen_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_strlen_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_strlen_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_strlen_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_strlen_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_strlen_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_strlen_ppc64_pcode(self):
        self.run_test("ppc64.pcode")

    def test_strlen_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_strlen_riscv64_pcode(self):
        self.run_test("riscv64.pcode")

    def test_strlen_xtensa_angr(self):
        self.run_test("xtensa.angr")

    def test_strlen_xtensa_pcode(self):
        self.run_test("xtensa.pcode")


class HookingTests(ScriptIntegrationTest):
    def run_test(self, arch, heckingMIPS64=False):
        if heckingMIPS64:
            # FIXME: Running hooking.mips64(el).panda.py IN THE INTEGRATION TESTS fails.
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

    def test_hooking_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_hooking_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_hooking_aarch64(self):
        self.run_test("aarch64")

    def test_hooking_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_hooking_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_hooking_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_hooking_armel(self):
        self.run_test("armel")

    def test_hooking_armel_angr(self):
        self.run_test("armel.angr")

    def test_hooking_armel_panda(self):
        self.run_test("armel.panda")

    def test_hooking_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_hooking_armhf(self):
        self.run_test("armhf")

    def test_hooking_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_hooking_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_hooking_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_hooking_i386(self):
        self.run_test("i386")

    def test_hooking_i386_angr(self):
        self.run_test("i386.angr")

    def test_hooking_i386_panda(self):
        self.run_test("i386.panda")

    def test_hooking_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_hooking_mips(self):
        self.run_test("mips")

    def test_hooking_mips_angr(self):
        self.run_test("mips.angr")

    def test_hooking_mips_panda(self):
        self.run_test("mips.panda")

    def test_hooking_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_hooking_mipsel(self):
        self.run_test("mipsel")

    def test_hooking_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_hooking_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_hooking_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_hooking_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_hooking_mips64_panda(self):
        # There is a crazy bug in panda/mips64;
        # it forgets the first character
        self.run_test("mips64.panda", heckingMIPS64=True)

    def test_hooking_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_hooking_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_hooking_mips64el_panda(self):
        # There is a crazy bug in panda/mips64;
        # it forgets the first character
        self.run_test("mips64el.panda", heckingMIPS64=True)

    def test_hooking_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_hooking_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_hooking_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_hooking_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_hooking_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_hooking_ppc64_pcode(self):
        self.run_test("ppc64.pcode")

    def test_hooking_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_hooking_riscv64_pcode(self):
        self.run_test("riscv64.pcode")

    def test_hooking_xtensa_angr(self):
        self.run_test("xtensa.angr")

    def test_hooking_xtensa_pcode(self):
        self.run_test("xtensa.pcode")


class ElfTests(ScriptIntegrationTest):
    def run_test(self, arch):
        self.command(f"python3 elf/elf.{arch}.py foobar")

    def test_elf_aarch64(self):
        self.run_test("aarch64")

    def test_elf_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_elf_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_elf_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_elf_amd64(self):
        self.run_test("amd64")

    def test_elf_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_elf_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_elf_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_elf_armel(self):
        self.run_test("armel")

    def test_elf_armel_angr(self):
        self.run_test("armel.angr")

    def test_elf_armel_panda(self):
        self.run_test("armel.panda")

    def test_elf_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_elf_armhf(self):
        self.run_test("armhf")

    def test_elf_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_elf_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_elf_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_elf_i386(self):
        self.run_test("i386")

    def test_elf_i386_angr(self):
        self.run_test("i386.angr")

    def test_elf_i386_panda(self):
        self.run_test("i386.panda")

    def test_elf_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_elf_mips(self):
        self.run_test("mips")

    def test_elf_mips_angr(self):
        self.run_test("mips.angr")

    def test_elf_mips_panda(self):
        self.run_test("mips.panda")

    def test_elf_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_elf_mipsel(self):
        self.run_test("mipsel")

    def test_elf_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_elf_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_elf_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_elf_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_elf_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_elf_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_elf_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_elf_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_elf_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_elf_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_elf_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_elf_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_elf_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_elf_ppc64_pcode(self):
        self.run_test("ppc64.pcode")

    def test_elf_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_elf_riscv64_pcode(self):
        self.run_test("riscv64.pcode")

    def test_elf_xtensa_angr(self):
        self.run_test("xtensa.angr")

    def test_elf_xtensa_pcode(self):
        self.run_test("xtensa.pcode")


class RelaTests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 rela/rela.{arch}.py")
        self.assertLineContainsStrings(stdout, "Hello, world!")

    def test_rela_amd64(self):
        self.run_test("amd64")

    def test_rela_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_rela_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_rela_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_rela_aarch64(self):
        self.run_test("aarch64")

    def test_rela_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_rela_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_rela_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_rela_armel(self):
        self.run_test("armel")

    def test_rela_armel_angr(self):
        self.run_test("armel.angr")

    def test_rela_armel_panda(self):
        self.run_test("armel.panda")

    def test_rela_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_rela_armhf(self):
        self.run_test("armhf")

    def test_rela_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_rela_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_rela_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_rela_i386(self):
        self.run_test("i386")

    def test_rela_i386_angr(self):
        self.run_test("i386.angr")

    def test_rela_i386_panda(self):
        self.run_test("i386.panda")

    def test_rela_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_rela_mips(self):
        self.run_test("mips")

    def test_rela_mips_angr(self):
        self.run_test("mips.angr")

    def test_rela_mips_panda(self):
        self.run_test("mips.panda")

    def test_rela_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_rela_mipsel(self):
        self.run_test("mipsel")

    def test_rela_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_rela_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_rela_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_rela_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_rela_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_rela_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_rela_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_rela_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_rela_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_rela_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_rela_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_rela_ppc_pcode(self):
        self.run_test("ppc.pcode")

    # NOTE: PowerPC64 relocations are not currently supported

    def test_rela_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_rela_riscv64_pcode(self):
        self.run_test("riscv64.pcode")

    # NOTE: xtensa doesn't have a glibc, so this test doesn't do.


class LinkElfTests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 link_elf/link_elf.{arch}.py 42")
        self.assertLineContainsStrings(stdout, "0x2a")

    def test_link_elf_aarch64(self):
        self.run_test("aarch64")

    def test_link_elf_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_link_elf_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_link_elf_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_link_elf_amd64(self):
        self.run_test("amd64")

    def test_link_elf_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_link_elf_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_link_elf_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_link_elf_armel(self):
        self.run_test("armel")

    def test_link_elf_armel_angr(self):
        self.run_test("armel.angr")

    def test_link_elf_armel_panda(self):
        self.run_test("armel.panda")

    def test_link_elf_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_link_elf_armhf(self):
        self.run_test("armhf")

    def test_link_elf_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_link_elf_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_link_elf_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_link_elf_i386(self):
        self.run_test("i386")

    def test_link_elf_i386_angr(self):
        self.run_test("i386.angr")

    def test_link_elf_i386_panda(self):
        self.run_test("i386.panda")

    def test_link_elf_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_link_elf_mips(self):
        self.run_test("mips")

    def test_link_elf_mips_angr(self):
        self.run_test("mips.angr")

    def test_link_elf_mips_panda(self):
        self.run_test("mips.panda")

    def test_link_elf_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_link_elf_mipsel(self):
        self.run_test("mipsel")

    def test_link_elf_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_link_elf_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_link_elf_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_link_elf_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_link_elf_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_link_elf_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_link_elf_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_link_elf_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_link_elf_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_link_elf_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_link_elf_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_link_elf_ppc_pcode(self):
        self.run_test("ppc.pcode")

    # NOTE: PowerPC64 relocations are not currently supported

    def test_link_elf_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_link_elf_riscv64_pcode(self):
        self.run_test("riscv64.pcode")

    # NOTE: xtensa doesn't have a glibc, so this test doesn't do.


class ElfCoreTests(ScriptIntegrationTest):
    def run_test(self, arch):
        self.command(f"python3 elf_core/elf_core.{arch}.py")

    def test_elf_core_aarch64(self):
        self.run_test("aarch64")

    def test_elf_core_amd64(self):
        self.run_test("amd64")

    def test_elf_core_armel(self):
        self.run_test("armel")

    def test_elf_core_armhf(self):
        self.run_test("armhf")

    def test_elf_core_i386(self):
        self.run_test("i386")

    def test_elf_core_mips(self):
        self.run_test("mips")

    def test_elf_core_mipsel(self):
        self.run_test("mipsel")

    def test_elf_core_mips64(self):
        self.run_test("mips64")

    def test_elf_core_mips64el(self):
        self.run_test("mips64el")

    def test_elf_core_ppc(self):
        self.run_test("ppc")

    def test_elf_core_ppc64(self):
        self.run_test("ppc64")

    # NOTE: RiscV doesn't produce a core file when asked.

    # NOTE: Xtensa is missing libc


class PETests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 pe/pe.{arch}.py")
        self.assertLineContainsStrings(stdout, "Hello, world!")

    def test_pe_amd64(self):
        self.run_test("amd64")

    def test_pe_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_pe_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_pe_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_pe_i386(self):
        self.run_test("i386")

    def test_pe_i386_angr(self):
        self.run_test("i386.angr")

    def test_pe_i386_panda(self):
        self.run_test("i386.panda")

    def test_pe_i386_pcode(self):
        self.run_test("i386.pcode")


class FloatsTests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 floats/floats.{arch}.py 2.2 1.1")
        self.assertLineContainsStrings(stdout, "3.3")

    def test_floats_aarch64(self):
        self.run_test("aarch64")

    def test_floats_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_floats_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_floats_amd64(self):
        self.run_test("amd64")

    def test_floats_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_floats_amd64_pcode(self):
        self.run_test("amd64.pcode")

    # NOTE: armel has no FPU, so no tests

    # NOTE: Unicorn does not support armhf float instructions

    def test_floats_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_floats_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_floats_i386(self):
        self.run_test("i386")

    def test_floats_i386_angr(self):
        self.run_test("i386.angr")

    def test_floats_i386_pcode(self):
        self.run_test("i386.pcode")

    # NOTE: mips be crazy

    # NOTE: No idea about PPC

    # NOTE: I can't get the assembler to build riscv64 FPU code

    # NOTE: xtensa has no FPU, so no tests


class SyscallTests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 syscall/syscall.{arch}.py")
        self.assertLineContainsStrings(stdout, "Executing syscall")
        self.assertLineContainsStrings(stdout, "Executing a write syscall")

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
            f"afl-showmap -C -t 10000 -U -m none -i fuzz/fuzz_inputs -o /dev/stdout -- python3 fuzz/afl_fuzz.{arch}.py @@",
            error=False,
        )
        for line in lines:
            self.assertLineContainsStrings(stdout, line)

    def test_fuzz_amd64(self):
        self.run_fuzz("amd64")

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


import json


class TraceExecutionTests(ScriptIntegrationTest):
    te_script = "trace_executor/trace_test.py"

    def run_trace_test(
        self, num_insns, buflen, create_heap, fortytwos, randomize_regs, seed
    ):
        stdout, stderr = self.command(
            f"python3 trace_executor/trace_test.py {num_insns} {buflen} {create_heap} {fortytwos} {randomize_regs} {seed}"
        )
        return (stdout, stderr)

    def get_trace(
        self, num_insns, buflen, create_heap, fortytwos, randomize_regs, seed
    ):
        stdout, stderr = self.run_trace_test(
            num_insns, buflen, create_heap, fortytwos, randomize_regs, seed
        )
        trace = []
        exceptions = []
        for line in stderr.split("\n"):
            # print(f" stder: {line}")
            foo = re.search("single step at (0x[0-9a-f]+)", line)
            if foo:
                trace.append(int(foo.groups()[0], 16))
            # [+] {"content": {"tr
            if "content" in line:
                content = json.loads(line[4:])["content"]
                if (
                    content["class"]
                    == "smallworld.analyses.trace_execution.TraceExecutionHint"
                ):
                    if content["exception"] is not None:
                        e = content["exception"]
                        ec = content["exception_class"]
                        pc = e["pc"]
                        exceptions.append((pc, ec))
        return (trace, exceptions)

    def get_cmp_br(
        self, num_insns, buflen, create_heap, fortytwos, randomize_regs, seed
    ):
        stdout, stderr = self.run_trace_test(
            num_insns, buflen, create_heap, fortytwos, randomize_regs, seed
        )
        branches = 0
        cmps = {}
        imms = {}
        for line in stderr.split("branch"):
            foo = re.search('": true', line)
            if foo:
                branches += 1
            foo = re.search('"pc": ([0-9]+)', line)
            if foo:
                pc = int(foo.groups()[0])
            foo = re.search(r'"cmp": \[(.*)\], "immediates', line)
            if foo:
                cmpi = foo.groups()[0]
                if cmpi == "":
                    continue
                c = eval(cmpi)
                if pc not in cmps:
                    cmps[pc] = [c]
                else:
                    cmps[pc].append(c)
            foo = re.search(r'"immediates": (\[.*\]), "mnemonic"', line)
            if foo:
                i = eval(foo.groups()[0])
                if len(i) > 0:
                    if pc not in imms:
                        imms[pc] = [i]
                    else:
                        imms[pc].append(i)

        def sort_kl(kl):
            ks = [x for x in kl.keys()]
            ks.sort()
            kll = []
            for k in ks:
                l1 = kl[k]
                l1.sort()
                kll.append((k, l1))
            return kll

        cmps = sort_kl(cmps)
        imms = sort_kl(imms)
        return (cmps, imms, branches)

    def compare_traces(self, tr1, tr2, same_is_correct, msg):
        # tr1, tr2 are traces (lists of integer program counters)
        # same_is_correct is a bool: true means we expect these traces to be the same
        # false, means we expect them to differ
        # msg is a message
        l1 = len(tr1)
        l2 = len(tr2)
        # if l1 == 0 or l2 == 0:
        #     breakpoint()
        first_mismatch = None
        for i in range(min(l1, l2)):
            if tr1[i] == tr2[i]:
                continue
            first_mismatch = i
            break
        if l1 != l2:
            if same_is_correct:
                raise AssertionError(
                    f"{msg}, traces should be identical but are not of same length? {l1}, {l2}"
                )
            else:
                # good
                pass
        if first_mismatch is not None:
            if same_is_correct:
                # breakpoint()
                tms = ""
                tms += "Trace mismatch at **:\n"
                for j in range(max(0, first_mismatch - 3), i + 1):
                    if j == i:
                        tms += f"{j} {i} ** "
                    else:
                        tms += f"{j} {i}    "
                    tms += f"0x{tr1[j]:x} | 0x{tr2[j]:x}"
                # breakpoint()
                raise AssertionError(f"{msg}, traces disagree at index {i}: \n {tms}")
            else:
                # good
                pass

    def test_trace_is_correct_no_heap(self):
        # This test assumes this is the version of ahme-x86_64.bin:
        # % md5sum ahme-x86_64.bin
        # ffe4930bb1bb00b720dc725b3c1edbf6  ahme-x86_64.bin

        # for these cmdline args to trace_execution.py,
        # note we have no heap here so we should see a memory unavailable
        (tr, exc) = self.get_trace(100, 12, False, False, False, 1234)
        # then this should be the trace followed.
        # [hand verified by TRL 7-23-2025]

        # print("tr_noheap=[")
        # for i in range(len(tr)):
        #     if ((i % 8) == 0):
        #         print("")
        #     print(f"0x{tr[i]:x}, ", end="")
        # print("]")
        tr_no_heap = [
            0x2169,
            0x216D,
            0x216E,
            0x2171,
            0x2175,
            0x2178,
            0x217F,
            0x2183,
            0x2189,
            0x2190,
            0x2202,
            0x2205,
            0x2208,
            0x2192,
            0x2195,
            0x2198,
            0x219C,
            0x219F,
        ]
        # breakpoint()
        self.compare_traces(
            tr, tr_no_heap, True, "Checking trace 1 correctness with ground truth"
        )
        found = False
        for pc, ec in exc:
            if (pc == 0x219F) and (
                ec
                == "<class 'smallworld.emulators.unicorn.unicorn.UnicornEmulationMemoryReadError'>"
            ):
                found = True
        if not found:
            raise AssertionError(
                f"Didn't observe UnicornEmulationMemoryReadError exception @ {0x219f}"
            )

    def test_trace_is_correct_1(self):
        # This test assumes this is the version of ahme-x86_64.bin:
        # % md5sum ahme-x86_64.bin
        # ffe4930bb1bb00b720dc725b3c1edbf6  ahme-x86_64.bin

        # for these cmdline args to trace_execution.py,
        (tr, exc) = self.get_trace(100, 12, True, False, False, 1234)
        # then this should be the trace followed.
        # [hand verified by TRL 7-23-2025]
        correct_trace = [
            0x2169,
            0x216D,
            0x216E,
            0x2171,
            0x2175,
            0x2178,
            0x217F,
            0x2183,
            0x2189,
            0x2190,
            0x2202,
            0x2205,
            0x2208,
            0x2192,
            0x2195,
            0x2198,
            0x219C,
            0x219F,
            0x21A2,
            0x21A7,
            0x21A9,
            0x21AB,
            0x21AF,
            0x21B1,
            0x21B4,
            0x21B6,
            0x21B8,
            0x21BA,
            0x21BC,
            0x21BE,
            0x21C0,
            0x21C2,
            0x21D2,
            0x21D5,
            0x21D7,
            0x21DA,
            0x21DC,
            0x21DE,
            0x21E0,
            0x21E3,
            0x21E6,
            0x21E9,
            0x21ED,
            0x21F0,
            0x21F3,
            0x21F5,
            0x21FE,
            0x2202,
            0x2205,
            0x2208,
            0x2192,
            0x2195,
            0x2198,
            0x219C,
            0x219F,
            0x21A2,
            0x21A7,
            0x21A9,
            0x21AB,
            0x21AF,
            0x21B1,
            0x21B4,
            0x21B6,
            0x21B8,
            0x21BA,
            0x21BC,
            0x21BE,
            0x21C0,
            0x21C2,
            0x21D2,
            0x21D5,
            0x21D7,
            0x21DA,
            0x21DC,
            0x21DE,
            0x21E0,
            0x21E3,
            0x21E6,
            0x21E9,
            0x21ED,
            0x21F0,
            0x21F3,
            0x21F5,
            0x21FE,
            0x2202,
            0x2205,
            0x2208,
            0x2192,
            0x2195,
            0x2198,
            0x219C,
            0x219F,
            0x21A2,
            0x21A7,
            0x21A9,
            0x21AB,
            0x21AF,
            0x21B1,
            0x21B4,
        ]
        self.compare_traces(
            tr, correct_trace, True, "Checking trace 1 correctness with ground truth"
        )

    def test_trace_is_correct_2(self):
        # This test assumes this is the version of ahme-x86_64.bin:
        # % md5sum ahme-x86_64.bin
        # ffe4930bb1bb00b720dc725b3c1edbf6  ahme-x86_64.bin

        # same as _1 but with different cmdline
        (tr, exc) = self.get_trace(100, 13, True, False, False, 1234)
        correct_trace = [
            0x2169,
            0x216D,
            0x216E,
            0x2171,
            0x2175,
            0x2178,
            0x217F,
            0x2183,
            0x220C,
            0x2213,
            0x2254,
            0x2257,
            0x225A,
            0x2215,
            0x2218,
            0x221B,
            0x221F,
            0x2222,
            0x2225,
            0x222A,
            0x222C,
            0x222E,
            0x2232,
            0x2235,
            0x2237,
            0x223A,
            0x223C,
            0x2241,
            0x2244,
            0x2246,
            0x2248,
            0x224A,
            0x224D,
            0x2250,
            0x2254,
            0x2257,
            0x225A,
            0x2215,
            0x2218,
            0x221B,
            0x221F,
            0x2222,
            0x2225,
            0x222A,
            0x222C,
            0x222E,
            0x2232,
            0x2235,
            0x2237,
            0x223A,
            0x223C,
            0x2241,
            0x2244,
            0x2246,
            0x2248,
            0x224A,
            0x224D,
            0x2250,
            0x2254,
            0x2257,
            0x225A,
            0x2215,
            0x2218,
            0x221B,
            0x221F,
            0x2222,
            0x2225,
            0x222A,
            0x222C,
            0x222E,
            0x2232,
            0x2235,
            0x2237,
            0x223A,
            0x223C,
            0x2241,
            0x2244,
            0x2246,
            0x2248,
            0x224A,
            0x224D,
            0x2250,
            0x2254,
            0x2257,
            0x225A,
            0x2215,
            0x2218,
            0x221B,
            0x221F,
            0x2222,
            0x2225,
            0x222A,
            0x222C,
            0x222E,
            0x2232,
            0x2235,
            0x2237,
            0x223A,
            0x223C,
        ]
        self.compare_traces(
            tr, correct_trace, True, "Checking trace 2 correctness with ground truth"
        )

    def test_trace_reproduces(self):
        # trace execution twice with same seed; should get exact same trace
        (tr1, exc1) = self.get_trace(100, 12, True, True, True, 1234)
        (tr2, exc2) = self.get_trace(100, 12, True, True, True, 1234)
        # here, we expect the traces to be identical
        self.compare_traces(tr1, tr2, True, "Checking trace generation is reproducable")

    def test_trace_change_seed(self):
        # if we change the seed when we are randomizing regs, then, for rest of these cmdline args, we should see a different trace
        (tr1, exc1) = self.get_trace(100, 12, True, True, True, 1234)
        (tr2, exc2) = self.get_trace(100, 12, True, True, True, 12345)
        # here, we expect the traces to be different
        self.compare_traces(tr1, tr2, False, "Checking traces diverge")

    def test_branch_and_cmp_info(self):
        # This test assumes this is the version of ahme-x86_64.bin:
        # % md5sum ahme-x86_64.bin
        # ffe4930bb1bb00b720dc725b3c1edbf6  ahme-x86_64.bin
        (cmps, imms, brs) = self.get_cmp_br(100, 12, True, True, True, 1234)
        # trace should emit this cmp/branch/imm info
        truth_cmps = [
            (
                4479,
                [
                    (
                        [
                            "BSIDMemoryReference",
                            {
                                "base": "rbp",
                                "index": None,
                                "offset": -28,
                                "scale": 1,
                                "size": 4,
                            },
                            [12, 0, 0, 0],
                        ],
                        ["Register", {"name": "rbp"}, 24568],
                    )
                ],
            ),
            (
                4544,
                [["Register", {"name": "al"}, 0], ["Register", {"name": "al"}, 254]],
            ),
            (
                4595,
                [["Register", {"name": "al"}, 42], ["Register", {"name": "al"}, 185]],
            ),
            (
                4613,
                [
                    (
                        ["Register", {"name": "eax"}, 0],
                        [
                            "BSIDMemoryReference",
                            {
                                "base": "rbp",
                                "index": None,
                                "offset": -28,
                                "scale": 1,
                                "size": 4,
                            },
                            [12, 0, 0, 0],
                        ],
                        ["Register", {"name": "rbp"}, 24568],
                    ),
                    (
                        ["Register", {"name": "eax"}, 1],
                        [
                            "BSIDMemoryReference",
                            {
                                "base": "rbp",
                                "index": None,
                                "offset": -28,
                                "scale": 1,
                                "size": 4,
                            },
                            [12, 0, 0, 0],
                        ],
                        ["Register", {"name": "rbp"}, 24568],
                    ),
                    (
                        ["Register", {"name": "eax"}, 2],
                        [
                            "BSIDMemoryReference",
                            {
                                "base": "rbp",
                                "index": None,
                                "offset": -28,
                                "scale": 1,
                                "size": 4,
                            },
                            [12, 0, 0, 0],
                        ],
                        ["Register", {"name": "rbp"}, 24568],
                    ),
                ],
            ),
        ]
        truth_imms = [
            (0x217F, [[12]]),
            (0x21F3, [[42], [42]]),
        ]
        # truth_imms = [(4479, [[12]]), (4595, [[42], [42]])]
        truth_brs = 8
        for pc1, rest1 in truth_cmps:
            for pc2, rest2 in cmps:
                if pc1 != pc2:
                    continue
                # breakpoint()
                l1 = len(rest1)
                l2 = len(rest2)
                disagree = False
                if l1 != l2:
                    disagree = True
                    num_same = 0
                    for e1 in rest1:
                        for e2 in rest2:
                            if e1 == e2:
                                num_same += 1
                    if num_same != l1:
                        disagree = True
                if disagree:
                    print("discrepency found in compare info:")
                    print(f"  truth:    {pc1:x} {rest1}")
                    print(f"  observed: {pc2:x} {rest2}")
                    raise AssertionError("Compare info disagrees with truth")
        if not (truth_imms == imms):

            def immstr(immi):
                ims = "["
                for pc, l in immi:
                    ims += f"(0x{pc:x} {l}), "
                ims += "]"
                return ims

            raise AssertionError(
                f"""Immediate info disagrees with truth
  truth:    {immstr(truth_imms)}
  observed: {immstr(imms)}"""
            )
        if not (truth_brs == brs):
            raise AssertionError(
                """Number of true branches taken disagrees with truth
  truth:    {truth_brs}
  observed: {brs}"""
            )


class ColorizerTests(ScriptIntegrationTest):
    ct_script = "colorizer/colorizer_test.py"
    #   10 47 56 False 1234

    def run_colorizer_test(self, num_micro_execs, num_insns, buflen, fortytwos, seed):
        stdout, stderr = self.command(
            f"python3 colorizer/colorizer_test.py {num_micro_execs} {num_insns} {buflen} {fortytwos} {seed}"
        )
        return (stdout, stderr)

    def get_color_info(self, num_micro_execs, num_insns, buflen, fortytwos, seed):
        stdout, stderr = self.run_colorizer_test(10, 37, 13, True, 1234)

        mem_hints = set([])
        reg_hints = set([])

        for line in stderr.split("\n"):
            if "summary" not in line:
                continue
            foo = re.search(
                '"message": "(.*)", "pc": ([0-9]+), "color": ([0-9]+), .* "class": "(.*)"}}',
                line,
            )
            if foo:
                (message, pcs, colors, cls) = foo.groups()
                if "DynamicMemoryValueSummaryHint" in cls:
                    foo = re.search(
                        r'"base": "(.*)", "index": "(.*)", "scale": ([0-9-]+), "offset": ([0-9-]+)',
                        line,
                    )
                    assert foo is not None
                    (base, index, scale, offset) = foo.groups()
                    mem_hints.add((message, pcs, colors, base, index, scale, offset))
                else:
                    assert "DynamicRegisterValueSummaryHint" in cls
                    foo = re.search('"reg_name": "(.*)", "class', line)
                    assert foo is not None
                    reg_name = foo.groups()[0]
                    reg_hints.add((message, pcs, colors, reg_name))

        return (mem_hints, reg_hints)

    def check(self, truth, observed, msg):
        if not (truth == observed):
            raise AssertionError(
                f"""Colorizer observed output disagrees with truth for {msg}.
Got
{observed}
Expected
{truth}"""
            )

    def test_colors_1(self):
        (mem_hints, reg_hints) = self.get_color_info(10, 37, 13, True, 1234)

        mem_hints_truth = {
            ("read-flow-summary", "4635", "3", "rbp", "None", "1", "-24"),
            ("write-copy-summary", "4465", "3", "rbp", "None", "1", "-24"),
            ("read-def-summary", "4642", "4", "rax", "None", "1", "0"),
        }
        reg_hints_truth = {
            ("read-flow-summary", "4680", "4", "ecx"),
            ("write-copy-summary", "4639", "3", "rax"),
            ("read-def-summary", "4465", "3", "rdi"),
            ("write-def-summary", "4461", "2", "rsp"),
            ("read-flow-summary", "4676", "4", "eax"),
            ("write-copy-summary", "4668", "4", "ecx"),
            ("write-copy-summary", "4676", "4", "ecx"),
            ("read-flow-summary", "4650", "5", "ecx"),
            ("read-flow-summary", "4685", "2", "rbp"),
            ("write-copy-summary", "4678", "4", "eax"),
            ("read-flow-summary", "4661", "4", "edx"),
            ("read-flow-summary", "4678", "4", "edx"),
            ("write-copy-summary", "4650", "5", "eax"),
            ("read-flow-summary", "4629", "2", "rbp"),
            ("read-flow-summary", "4639", "3", "rax"),
            ("read-flow-summary", "4472", "2", "rbp"),
            ("read-flow-summary", "4673", "4", "ecx"),
            ("read-flow-summary", "4663", "4", "cl"),
            ("write-def-summary", "4652", "6", "ax"),
            ("read-def-summary", "4461", "1", "rsp"),
            ("read-flow-summary", "4688", "2", "rbp"),
            ("read-flow-summary", "4635", "2", "rbp"),
            ("read-flow-summary", "4469", "2", "rbp"),
            ("read-flow-summary", "4680", "4", "eax"),
            ("read-flow-summary", "4654", "6", "ax"),
            ("write-copy-summary", "4635", "3", "rax"),
            ("read-flow-summary", "4652", "4", "dl"),
            ("write-copy-summary", "4661", "4", "ecx"),
            ("read-flow-summary", "4692", "2", "rbp"),
            ("write-copy-summary", "4673", "4", "eax"),
            ("read-flow-summary", "4695", "2", "rbp"),
            ("read-flow-summary", "4465", "2", "rbp"),
            ("write-copy-summary", "4642", "4", "edx"),
            ("write-copy-summary", "4462", "2", "rbp"),
            ("write-def-summary", "4645", "5", "ecx"),
            ("read-flow-summary", "4462", "2", "rsp"),
            ("read-flow-summary", "4652", "5", "al"),
            ("read-flow-summary", "4642", "3", "rax"),
            ("read-flow-summary", "4479", "2", "rbp"),
            ("read-flow-summary", "4620", "2", "rbp"),
        }
        self.check(mem_hints_truth, mem_hints, "mem_hints")
        self.check(reg_hints_truth, reg_hints, "reg_hints")

    def test_colors_2(self):
        (mem_hints, reg_hints) = self.get_color_info(10, 52, 12, True, 1234)

        mem_hints_truth = {
            ("read-flow-summary", "4635", "3", "rbp", "None", "1", "-24"),
            ("write-copy-summary", "4465", "3", "rbp", "None", "1", "-24"),
            ("read-def-summary", "4642", "4", "rax", "None", "1", "0"),
        }
        reg_hints_truth = {
            ("read-flow-summary", "4692", "2", "rbp"),
            ("write-copy-summary", "4678", "4", "eax"),
            ("write-copy-summary", "4673", "4", "eax"),
            ("write-copy-summary", "4668", "4", "ecx"),
            ("read-flow-summary", "4663", "4", "cl"),
            ("write-copy-summary", "4639", "3", "rax"),
            ("write-def-summary", "4461", "2", "rsp"),
            ("read-flow-summary", "4680", "4", "eax"),
            ("write-copy-summary", "4642", "4", "edx"),
            ("read-flow-summary", "4465", "2", "rbp"),
            ("read-flow-summary", "4629", "2", "rbp"),
            ("read-flow-summary", "4673", "4", "ecx"),
            ("write-def-summary", "4652", "6", "ax"),
            ("read-flow-summary", "4676", "4", "eax"),
            ("read-flow-summary", "4685", "2", "rbp"),
            ("read-flow-summary", "4642", "3", "rax"),
            ("read-flow-summary", "4652", "4", "dl"),
            ("read-flow-summary", "4462", "2", "rsp"),
            ("write-copy-summary", "4676", "4", "ecx"),
            ("read-flow-summary", "4639", "3", "rax"),
            ("write-def-summary", "4645", "5", "ecx"),
            ("read-flow-summary", "4678", "4", "edx"),
            ("read-def-summary", "4461", "1", "rsp"),
            ("read-flow-summary", "4680", "4", "ecx"),
            ("read-flow-summary", "4635", "2", "rbp"),
            ("read-flow-summary", "4472", "2", "rbp"),
            ("read-flow-summary", "4652", "5", "al"),
            ("write-copy-summary", "4661", "4", "ecx"),
            ("read-flow-summary", "4479", "2", "rbp"),
            ("write-copy-summary", "4462", "2", "rbp"),
            ("read-flow-summary", "4620", "2", "rbp"),
            ("read-flow-summary", "4650", "5", "ecx"),
            ("read-def-summary", "4465", "3", "rdi"),
            ("read-flow-summary", "4695", "2", "rbp"),
            ("write-copy-summary", "4650", "5", "eax"),
            ("read-flow-summary", "4688", "2", "rbp"),
            ("read-flow-summary", "4469", "2", "rbp"),
            ("write-copy-summary", "4635", "3", "rax"),
            ("read-flow-summary", "4654", "6", "ax"),
            ("read-flow-summary", "4661", "4", "edx"),
        }
        self.check(mem_hints_truth, mem_hints, "mem_hints")
        self.check(reg_hints_truth, reg_hints, "reg_hints")


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
