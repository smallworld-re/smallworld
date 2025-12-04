import abc
import io
import os
import re
import subprocess
import typing
import unittest

from sphinx import application, errors

import smallworld


class DetailedCalledProcessError(Exception):
    def __init__(self, error: subprocess.CalledProcessError):
        self.error = error

    def __str__(self) -> str:
        return f"{self.error.__str__()}\n\nstdout:\n{self.error.stdout.decode()}\n\nstderr:\n{self.error.stderr.decode()}"


class ScriptIntegrationTest(unittest.TestCase):
    maxDiff = None

    def command(
        self,
        cmd: str,
        stdin: typing.Optional[str] = None,
        error: bool = True,
        cwd: typing.Optional[str] = None,
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

        if cwd is None:
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

    def assertStringsAbsent(self, output: str, *strings) -> None:
        """Assert that all lines contain none of these strings.

        Arguments:
            outputs: The output to check
            strings: One or more strings to match

        Raises:
            `AssertionError` if any line in `output` matches any string in `strings`.
        """
        for line in output.split("\n"):
            for string in strings:
                if string in line:
                    raise AssertionError(f"Line contains {string}:\n\n{output.strip()}")

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
        test_output(101, 0x321)
        test_output(65536, 0x21)


class CallTestsAngr(CallTests):
    def test_call_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_call_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_call_armel_angr(self):
        self.run_test("armel.angr")

    def test_call_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_call_i386_angr(self):
        self.run_test("i386.angr")

    def test_call_la64_angr(self):
        self.run_test("la64.angr", signext=True)

    def test_call_mips_angr(self):
        self.run_test("mips.angr")

    def test_call_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_call_mips64_angr(self):
        self.run_test("mips64.angr", signext=True)

    def test_call_mips64el_angr(self):
        self.run_test("mips64el.angr", signext=True)

    def test_call_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_call_ppc64_angr(self):
        self.run_test("ppc64.angr", signext=True)

    def test_call_riscv64_angr(self):
        self.run_test("riscv64.angr", signext=True)

    def test_call_xtensa_angr(self):
        self.run_test("xtensa.angr")


class CallTestsGhidra(CallTests):
    def test_call_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_call_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_call_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_call_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_call_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_call_la64_pcode(self):
        self.run_test("la64.pcode", signext=True)

    def test_call_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_call_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_call_mips64_pcode(self):
        self.run_test("mips64.pcode", signext=True)

    def test_call_mips64el_pcode(self):
        self.run_test("mips64el.pcode", signext=True)

    def test_call_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_call_ppc64_pcode(self):
        self.run_test("ppc64.pcode", signext=True)

    def test_call_riscv64_pcode(self):
        self.run_test("riscv64.pcode", signext=True)

    def test_call_xtensa_pcode(self):
        self.run_test("xtensa.pcode")


class CallTestsPanda(CallTests):
    def test_call_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_call_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_call_armel_panda(self):
        self.run_test("armel.panda")

    def test_call_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_call_i386_panda(self):
        self.run_test("i386.panda")

    def test_call_mips_panda(self):
        self.run_test("mips.panda")

    def test_call_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_call_mips64_panda(self):
        self.run_test("mips64.panda", signext=True)

    def test_call_mips64el_panda(self):
        self.run_test("mips64el.panda", signext=True)

    def test_call_ppc_panda(self):
        self.run_test("ppc.panda")


class CallTestsUnicorn(CallTests):
    def test_call_aarch64(self):
        self.run_test("aarch64")

    def test_call_amd64(self):
        self.run_test("amd64")

    def test_call_armel(self):
        self.run_test("armel")

    def test_call_armhf(self):
        self.run_test("armhf")

    def test_call_i386(self):
        self.run_test("i386")

    def test_call_mips(self):
        self.run_test("mips")

    def test_call_mipsel(self):
        self.run_test("mipsel")


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

    def test_dma_la64_angr(self):
        self.run_test("la64.angr")

    def test_dma_la64_pcode(self):
        self.run_test("la64.pcode")

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

    def test_la64_angr(self):
        self.run_test("la64.angr")

    def test_la64_pcode(self):
        self.run_test("la64.pcode")

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

    def test_stack_la64_angr(self):
        self.run_test("la64.angr", reg="a0", res="0xffff")

    def test_stack_la64_pcode(self):
        self.run_test("la64.pcode", reg="a0", res="0xffff")

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
    def test_unicorn(self):
        stdout, _ = self.command("python3 struct/struct.amd64.py")
        self.assertLineContainsStrings(stdout, "arg2 = 42")

    def test_panda(self):
        stdout, _ = self.command("python3 struct/struct.amd64.panda.py")
        self.assertLineContainsStrings(stdout, "arg2 = 42")


class BranchTests(ScriptIntegrationTest):
    def run_branch(self, arch, reg="eax"):
        stdout, _ = self.command(f"python3 branch/branch.{arch}.py 99")
        self.assertLineContainsStrings(stdout, reg, "0x0")

        stdout, _ = self.command(f"python3 branch/branch.{arch}.py 100")
        self.assertLineContainsStrings(stdout, reg, "0x1")

        stdout, _ = self.command(f"python3 branch/branch.{arch}.py 101")
        self.assertLineContainsStrings(stdout, reg, "0x0")


class BranchTestsAngr(BranchTests):
    def test_branch_aarch64_angr(self):
        self.run_branch("aarch64.angr", reg="w0")

    def test_branch_amd64_angr(self):
        self.run_branch("amd64.angr")

    def test_branch_armel_angr(self):
        self.run_branch("armel.angr", reg="r0")

    def test_branch_armhf_angr(self):
        self.run_branch("armhf.angr", reg="r0")

    def test_branch_i386_angr(self):
        self.run_branch("i386.angr")

    def test_branch_la64_angr(self):
        self.run_branch("la64.angr", reg="a0")

    def test_branch_mips_angr(self):
        self.run_branch("mips.angr", reg="v0")

    def test_branch_mipsel_angr(self):
        self.run_branch("mipsel.angr", reg="v0")

    def test_branch_mips64_angr(self):
        self.run_branch("mips64.angr", reg="v0")

    def test_branch_mips64el_angr(self):
        self.run_branch("mips64el.angr", reg="v0")

    def test_branch_ppc_angr(self):
        self.run_branch("ppc.angr", reg="r3")

    def test_branch_ppc64_angr(self):
        self.run_branch("ppc64.angr", reg="r3")

    def test_branch_riscv64_angr(self):
        self.run_branch("riscv64.angr", reg="a0")

    def test_branch_xtensa_angr(self):
        self.run_branch("xtensa.angr", reg="a2")


class BranchTestsGhidra(BranchTests):
    def test_branch_aarch64_pcode(self):
        self.run_branch("aarch64.pcode", reg="w0")

    def test_branch_amd64_pcode(self):
        self.run_branch("amd64.pcode")

    def test_branch_armel_pcode(self):
        self.run_branch("armel.pcode", reg="r0")

    def test_branch_armhf_pcode(self):
        self.run_branch("armhf.pcode", reg="r0")

    def test_branch_i386_pcode(self):
        self.run_branch("i386.pcode")

    def test_branch_la64_pcode(self):
        self.run_branch("la64.pcode", reg="a0")

    def test_branch_mips_pcode(self):
        self.run_branch("mips.pcode", reg="v0")

    def test_branch_mipsel_pcode(self):
        self.run_branch("mipsel.pcode", reg="v0")

    def test_branch_mips64_pcode(self):
        self.run_branch("mips64.pcode", reg="v0")

    def test_branch_mips64el_pcode(self):
        self.run_branch("mips64el.pcode", reg="v0")

    def test_branch_ppc_pcode(self):
        self.run_branch("ppc.pcode", reg="r3")

    def test_branch_ppc64_pcode(self):
        self.run_branch("ppc64.pcode", reg="r3")

    def test_branch_riscv64_pcode(self):
        self.run_branch("riscv64.pcode", reg="a0")

    def test_branch_xtensa_pcode(self):
        self.run_branch("xtensa.pcode", reg="a2")


class BranchTestsPanda(BranchTests):
    def test_branch_aarch64_panda(self):
        self.run_branch("aarch64.panda", reg="w0")

    def test_branch_amd64_panda(self):
        self.run_branch("amd64.panda")

    def test_branch_armel_panda(self):
        self.run_branch("armel.panda", reg="r0")

    def test_branch_armhf_panda(self):
        self.run_branch("armhf.panda", reg="r0")

    def test_branch_i386_panda(self):
        self.run_branch("i386.panda")

    def test_branch_mips_panda(self):
        self.run_branch("mips.panda", reg="v0")

    def test_branch_mipsel_panda(self):
        self.run_branch("mipsel.panda", reg="v0")

    def test_branch_mips64_panda(self):
        self.run_branch("mips64.panda", reg="v0")

    def test_branch_mips64el_panda(self):
        self.run_branch("mips64el.panda", reg="v0")

    def test_branch_ppc_panda(self):
        self.run_branch("ppc.panda", reg="r3")


class BranchTestsUnicorn(BranchTests):
    def test_branch_aarch64(self):
        self.run_branch("aarch64", reg="w0")

    def test_branch_amd64(self):
        self.run_branch("amd64")

    def test_branch_armel(self):
        self.run_branch("armel", reg="r0")

    def test_branch_armhf(self):
        self.run_branch("armhf", reg="r0")

    def test_branch_i386(self):
        self.run_branch("i386")

    def test_branch_mips(self):
        self.run_branch("mips", reg="v0")

    def test_branch_mipsel(self):
        self.run_branch("mipsel", reg="v0")


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

    def test_strlen_la64_angr(self):
        self.run_test("la64.angr")

    def test_strlen_la64_pcode(self):
        self.run_test("la64.pcode")

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

    def test_hooking_la64_angr(self):
        self.run_test("la64.angr")

    def test_hooking_la64_pcode(self):
        self.run_test("la64.pcode")

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


class MemhookTests(ScriptIntegrationTest):
    def run_test_64(self, arch):
        stdout, _ = self.command(f"python3 memhook/memhook.{arch}.py")
        self.assertLineContainsStrings(stdout, "foo: read 1 bytes at 0x1004")
        self.assertLineContainsStrings(stdout, "bar: read 8 bytes at 0x100c")
        self.assertLineContainsStrings(stdout, "baz: read 8 bytes at 0x1024")
        self.assertLineContainsStrings(stdout, "qux: read 8 bytes at 0x1030")

    def run_test_32(self, arch):
        stdout, _ = self.command(f"python3 memhook/memhook.{arch}.py")
        self.assertLineContainsStrings(stdout, "foo: read 1 bytes at 0x1004")
        self.assertLineContainsStrings(stdout, "bar: read 4 bytes at 0x1010")
        self.assertLineContainsStrings(stdout, "baz: read 4 bytes at 0x1024")
        self.assertLineContainsStrings(stdout, "qux: read 4 bytes at 0x1034")

    def test_aarch64(self):
        self.run_test_64("aarch64")

    def test_aarch64_angr(self):
        self.run_test_64("aarch64.angr")

    def test_aarch64_panda(self):
        self.run_test_64("aarch64.panda")

    def test_aarch64_ghidra(self):
        self.run_test_64("aarch64.ghidra")

    def test_amd64(self):
        self.run_test_64("amd64")

    def test_amd64_angr(self):
        self.run_test_64("amd64.angr")

    def test_amd64_panda(self):
        self.run_test_64("amd64.panda")

    def test_amd64_ghidra(self):
        self.run_test_64("amd64.ghidra")

    def test_armel(self):
        self.run_test_32("armel")

    def test_armel_angr(self):
        self.run_test_32("armel.angr")

    def test_armel_panda(self):
        self.run_test_32("armel.panda")

    def test_armel_ghidra(self):
        self.run_test_32("armel.ghidra")

    def test_armhf(self):
        self.run_test_32("armhf")

    def test_armhf_angr(self):
        self.run_test_32("armhf.angr")

    def test_armhf_panda(self):
        self.run_test_32("armhf.panda")

    def test_armhf_ghidra(self):
        self.run_test_32("armhf.ghidra")

    def test_i386(self):
        self.run_test_32("i386")

    def test_i386_angr(self):
        self.run_test_32("i386.angr")

    def test_i386_panda(self):
        self.run_test_32("i386.panda")

    def test_i386_ghidra(self):
        self.run_test_32("i386.ghidra")

    def test_la64_angr(self):
        self.run_test_64("la64.angr")

    def test_la64_ghidra(self):
        self.run_test_64("la64.ghidra")

    def test_mips(self):
        self.run_test_32("mips")

    def test_mips_angr(self):
        self.run_test_32("mips.angr")

    def test_mips_panda(self):
        self.run_test_32("mips.panda")

    def test_mips_ghidra(self):
        self.run_test_32("mips.ghidra")

    def test_mipsel(self):
        self.run_test_32("mipsel")

    def test_mipsel_angr(self):
        self.run_test_32("mipsel.angr")

    def test_mipsel_panda(self):
        self.run_test_32("mipsel.panda")

    def test_mipsel_ghidra(self):
        self.run_test_32("mipsel.ghidra")

    def test_mips64_angr(self):
        self.run_test_64("mips64.angr")

    def test_mips64_panda(self):
        # Broken; no idea why
        # self.run_test_64("mips64.panda")
        pass

    def test_mips64_ghidra(self):
        self.run_test_64("mips64.ghidra")
        pass

    def test_mips64el_angr(self):
        self.run_test_64("mips64el.angr")

    def test_mips64el_panda(self):
        # Broken; no idea why
        # self.run_test_64("mips64el.panda")
        pass

    def test_mips64el_ghidra(self):
        self.run_test_64("mips64el.ghidra")

    def test_ppc_angr(self):
        self.run_test_32("ppc.angr")

    def test_ppc_panda(self):
        self.run_test_32("ppc.panda")

    def test_ppc_ghidra(self):
        self.run_test_32("ppc.ghidra")

    def test_riscv64_angr(self):
        self.run_test_64("riscv64.angr")

    def test_riscv64_ghidra(self):
        self.run_test_64("riscv64.ghidra")


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

    def test_elf_la64_angr(self):
        self.run_test("la64.angr")

    def test_elf_la64_pcode(self):
        self.run_test("la64.pcode")

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

    def test_rela_la64_angr(self):
        self.run_test("la64.angr")

    def test_rela_la64_pcode(self):
        self.run_test("la64.pcode")

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

    def test_link_elf_la64_angr(self):
        self.run_test("la64.angr")

    def test_link_elf_la64_pcode(self):
        self.run_test("la64.pcode")

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

    #    def test_link_elf_mips64_angr(self):
    #        self.run_test("mips64.angr")
    #
    #    def test_link_elf_mips64_panda(self):
    #        self.run_test("mips64.panda")
    #
    #    def test_link_elf_mips64_pcode(self):
    #        self.run_test("mips64.pcode")
    #
    #    def test_link_elf_mips64el_angr(self):
    #        self.run_test("mips64el.angr")
    #
    #    def test_link_elf_mips64el_panda(self):
    #        self.run_test("mips64el.panda")
    #
    #    def test_link_elf_mips64el_pcode(self):
    #        self.run_test("mips64el.pcode")
    #
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


class ElfCoreLoadTests(ScriptIntegrationTest):
    def run_test(self, arch):
        self.command(f"python3 elf_core/load/elf_core.{arch}.py")

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


class ElfCoreActuateTests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 elf_core/actuate/elf_core.{arch}.py")
        self.assertLineContainsStrings(stdout, "foobar")

    def test_aarch64(self):
        self.run_test("aarch64")

    def test_aarch64_angr(self):
        self.run_test("aarch64.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_amd64(self):
        self.run_test("amd64")

    @unittest.skip("Problem loading rflags")
    def test_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_armel(self):
        self.run_test("armel")

    def test_armel_angr(self):
        self.run_test("armel.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_armel_panda(self):
        self.run_test("armel.panda")

    def test_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_armhf(self):
        self.run_test("armhf")

    def test_armhf_angr(self):
        self.run_test("armhf.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_armhf_pcode(self):
        self.run_test("armhf.pcode")

    @unittest.skip("Problem loading segment registers")
    def test_i386(self):
        self.run_test("i386")

    @unittest.skip("Problem loading eflags")
    def test_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_i386_panda(self):
        self.run_test("i386.panda")

    def test_i386_pcode(self):
        self.run_test("i386.pcode")

    # Can't actuate la64 to create a coredump

    def test_mips(self):
        self.run_test("mips")

    def test_mips_angr(self):
        self.run_test("mips.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mips_panda(self):
        self.run_test("mips.panda")

    def test_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_mipsel(self):
        self.run_test("mipsel")

    def test_mipsel_angr(self):
        self.run_test("mipsel.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_mips64_angr(self):
        self.run_test("mips64.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_mips64el_angr(self):
        self.run_test("mips64el.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_ppc64_angr(self):
        self.run_test("ppc.angr")

    def test_ppc64_pcode(self):
        self.run_test("ppc.pcode")

    # NOTE: RiscV doesn't produce a core file when asked.

    # NOTE: xtensa doesn't have a glibc, so this test doesn't do.


class PETests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 pe/pe.{arch}.py")
        stdout = "Hello, world!"
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


class LinkPETests(ScriptIntegrationTest):
    def run_test(self, arch):
        stdout, _ = self.command(f"python3 link_pe/link_pe.{arch}.py 42")
        self.assertLineContainsStrings(stdout, "0x2a")

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

    # NOTE: la64 doesn't have an FPU model

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

    def test_syscall_la64_angr(self):
        self.run_test("la64.angr")

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


class StaticBufferTests(ScriptIntegrationTest):
    def run_test(self, arch: str):
        stdout, _ = self.command(f"python3 static_buf/static_buf.{arch}.py")
        self.assertLineContainsStrings(stdout, "=0x4a1")

    def test_aarch64(self):
        self.run_test("aarch64")

    def test_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_amd64(self):
        self.run_test("amd64")

    def test_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_armel(self):
        self.run_test("armel")

    def test_armel_angr(self):
        self.run_test("armel.angr")

    def test_armel_panda(self):
        self.run_test("armel.panda")

    def test_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_armhf(self):
        self.run_test("armhf")

    def test_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_i386(self):
        self.run_test("i386")

    def test_i386_angr(self):
        self.run_test("i386.angr")

    def test_i386_panda(self):
        self.run_test("i386.panda")

    def test_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_la64_angr(self):
        self.run_test("la64.angr")

    def test_la64_pcode(self):
        self.run_test("la64.pcode")

    def test_mips(self):
        self.run_test("mips")

    def test_mips_angr(self):
        self.run_test("mips.angr")

    def test_mips_panda(self):
        self.run_test("mips.panda")

    def test_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_mipsel(self):
        self.run_test("mipsel")

    def test_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_ppc64_pcode(self):
        self.run_test("ppc64.pcode")

    def test_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_riscv64_pcode(self):
        self.run_test("riscv64.pcode")

    def test_xtensa_angr(self):
        self.run_test("xtensa.angr")

    def test_xtensa_pcode(self):
        self.run_test("xtensa.pcode")


class DelayTests(ScriptIntegrationTest):
    def run_test(self, arch: str):
        self.command(f"python3 delay/delay.{arch}.py")

    def test_mips(self):
        self.run_test("mips")

    def test_mips_angr(self):
        self.run_test("mips.angr")

    def test_mips_panda(self):
        self.run_test("mips.panda")

    def test_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_mipsel(self):
        self.run_test("mipsel")

    def test_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_mips64el_pcode(self):
        self.run_test("mips64el.pcode")


class ExitpointTests(ScriptIntegrationTest):
    def run_test(self, arch: str):
        self.command(f"python3 exitpoint/exitpoint.{arch}.py")

    def test_aarch64(self):
        self.run_test("aarch64")

    def test_aarch64_angr(self):
        self.run_test("aarch64.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_amd64(self):
        self.run_test("amd64")

    def test_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_armel(self):
        self.run_test("armel")

    def test_armel_angr(self):
        self.run_test("armel.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_armel_panda(self):
        self.run_test("armel.panda")

    def test_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_armhf(self):
        self.run_test("armhf")

    def test_armhf_angr(self):
        self.run_test("armhf.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_i386(self):
        self.run_test("i386")

    def test_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_i386_panda(self):
        self.run_test("i386.panda")

    def test_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_la64_angr(self):
        self.run_test("la64.angr")

    def test_la64_pcode(self):
        self.run_test("la64.pcode")

    def test_mips(self):
        self.run_test("mips")

    def test_mips_angr(self):
        self.run_test("mips.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mips_panda(self):
        self.run_test("mips.panda")

    def test_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_mipsel(self):
        self.run_test("mipsel")

    def test_mipsel_angr(self):
        self.run_test("mipsel.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_mips64_angr(self):
        self.run_test("mips64.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_mips64el_angr(self):
        self.run_test("mips64el.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_ppc64_pcode(self):
        self.run_test("ppc64.pcode")

    def test_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_riscv64_pcode(self):
        self.run_test("riscv64.pcode")


class UnmappedTests(ScriptIntegrationTest):
    def run_test(self, arch: str):
        self.command(f"python3 unmapped/unmapped.{arch}.py")

    def test_aarch64(self):
        self.run_test("aarch64")

    def test_aarch64_angr(self):
        self.run_test("aarch64.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_aarch64_pcode(self):
        self.run_test("aarch64.pcode")

    def test_amd64(self):
        self.run_test("amd64")

    def test_amd64_angr(self):
        self.run_test("amd64.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_amd64_pcode(self):
        self.run_test("amd64.pcode")

    def test_armel(self):
        self.run_test("armel")

    def test_armel_angr(self):
        self.run_test("armel.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_armel_panda(self):
        self.run_test("armel.panda")

    def test_armel_pcode(self):
        self.run_test("armel.pcode")

    def test_armhf(self):
        self.run_test("armhf")

    def test_armhf_angr(self):
        self.run_test("armhf.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_armhf_pcode(self):
        self.run_test("armhf.pcode")

    def test_i386(self):
        self.run_test("i386")

    def test_i386_angr(self):
        self.run_test("i386.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_i386_panda(self):
        self.run_test("i386.panda")

    def test_i386_pcode(self):
        self.run_test("i386.pcode")

    def test_la64_angr(self):
        self.run_test("la64.angr")

    def test_la64_pcode(self):
        self.run_test("la64.pcode")

    def test_mips(self):
        self.run_test("mips")

    def test_mips_angr(self):
        self.run_test("mips.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mips_panda(self):
        self.run_test("mips.panda")

    def test_mips_pcode(self):
        self.run_test("mips.pcode")

    def test_mipsel(self):
        self.run_test("mipsel")

    def test_mipsel_angr(self):
        self.run_test("mipsel.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_mipsel_pcode(self):
        self.run_test("mipsel.pcode")

    def test_mips64_angr(self):
        self.run_test("mips64.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_mips64_pcode(self):
        self.run_test("mips64.pcode")

    def test_mips64el_angr(self):
        self.run_test("mips64el.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_mips64el_pcode(self):
        self.run_test("mips64el.pcode")

    def test_ppc_angr(self):
        self.run_test("ppc.angr")

    @unittest.skip("Waiting for panda-ng")
    def test_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_ppc_pcode(self):
        self.run_test("ppc.pcode")

    def test_ppc64_angr(self):
        self.run_test("ppc64.angr")

    def test_ppc64_pcode(self):
        self.run_test("ppc64.pcode")

    def test_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_riscv64_pcode(self):
        self.run_test("riscv64.pcode")


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
                "022192:1",
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


class SysVModelTests(ScriptIntegrationTest):
    def run_test(self, arch):
        self.command(f"python3 sysv/sysv.{arch}.py")

    def test_aarch64(self):
        self.run_test("aarch64")

    def test_amd64(self):
        self.run_test("amd64")

    def test_armel(self):
        self.run_test("armel")

    def test_armhf(self):
        self.run_test("armhf")

    def test_i386(self):
        self.run_test("i386")

    def test_la64(self):
        self.run_test("la64")

    def test_mips(self):
        self.run_test("mips")

    def test_mipsel(self):
        self.run_test("mipsel")

    def test_mips64(self):
        self.run_test("mips64")

    def test_mips64el(self):
        self.run_test("mips64el")

    def test_ppc(self):
        self.run_test("ppc")

    def test_riscv64(self):
        self.run_test("riscv64")


class AbsLibraryModelTest(ScriptIntegrationTest):
    """Test case for library models.

    These all have an identical interface, and there are a metric ton of them.
    """

    @property
    @abc.abstractmethod
    def library(self) -> str:
        """Name of the library this belongs to"""
        return ""

    @property
    @abc.abstractmethod
    def function(self) -> str:
        """Name of the function to test"""
        return ""

    @abc.abstractmethod
    def run_test(self, arch):
        pass

    def test_aarch64(self):
        self.run_test("aarch64")

    def test_amd64(self):
        self.run_test("amd64")

    def test_armel(self):
        self.run_test("armel")

    def test_armhf(self):
        self.run_test("armhf")

    def test_i386(self):
        self.run_test("i386")

    def test_la64(self):
        self.run_test("la64")

    def test_mips(self):
        self.run_test("mips")

    def test_mipsel(self):
        self.run_test("mipsel")

    def test_mips64(self):
        self.run_test("mips64")

    def test_mips64el(self):
        self.run_test("mips64el")

    def test_ppc(self):
        self.run_test("ppc")

    def test_riscv64(self):
        self.run_test("riscv64")


class LibraryModelTest(AbsLibraryModelTest):
    def run_test(self, arch):
        # These are all designed to either take no arguments,
        # or to run a positive test if fed "foobar", and a negative test if fed "bazquxx"
        self.command(
            f"python3 {self.library}/{self.function}/{self.function}.{arch}.py foobar"
        )
        self.command(
            f"python3 {self.library}/{self.function}/{self.function}.{arch}.py bazquxx"
        )


class OneArgLibraryModelTest(AbsLibraryModelTest):
    def run_test(self, arch):
        # These are all designed to either take no arguments,
        # or to run a positive test if fed "foobar"
        self.command(
            f"echo 'foobar' | python3 {self.library}/{self.function}/{self.function}.{arch}.py"
        )


class NoArgLibraryModelTest(AbsLibraryModelTest):
    def run_test(self, arch):
        self.command(
            f"TZ=UTC python3 {self.library}/{self.function}/{self.function}.{arch}.py"
        )


class C99LibcTests(NoArgLibraryModelTest):
    library = "c99"
    function = "libc"

    def run_test(self, arch):
        _, stderr = self.command(
            f"TZ=UTC python3 {self.library}/{self.function}/{self.function}.{arch}.py"
        )

        self.assertLineContainsStrings(stderr, "Harness requires atexit")
        self.assertLineContainsStrings(stderr, "Harness requires vprintf")
        self.assertStringsAbsent(stderr, "Harness requires system")


class C99AbsTests(NoArgLibraryModelTest):
    library = "c99"
    function = "abs"


class C99AbortTests(NoArgLibraryModelTest):
    library = "c99"
    function = "abort"


class C99AtexitTests(NoArgLibraryModelTest):
    library = "c99"
    function = "atexit"


class C99AtoiTests(NoArgLibraryModelTest):
    library = "c99"
    function = "atoi"


class C99AtolTests(NoArgLibraryModelTest):
    library = "c99"
    function = "atol"


class C99AtollTests(NoArgLibraryModelTest):
    library = "c99"
    function = "atoll"


class C99CallocTests(NoArgLibraryModelTest):
    library = "c99"
    function = "calloc"


class C99ExitTests(NoArgLibraryModelTest):
    library = "c99"
    function = "exit"


class C99FreeTests(NoArgLibraryModelTest):
    library = "c99"
    function = "free"


class C99GetenvTests(AbsLibraryModelTest):
    library = "c99"
    function = "getenv"

    def run_test(self, arch):
        _, stderr = self.command(
            f"python3 {self.library}/{self.function}/{self.function}.{arch}.py"
        )
        self.assertLineContainsStrings(stderr, "getenv(foobar);")


class C99LabsTests(NoArgLibraryModelTest):
    library = "c99"
    function = "labs"


class C99LlabsTests(NoArgLibraryModelTest):
    library = "c99"
    function = "llabs"


class C99MallocTests(NoArgLibraryModelTest):
    library = "c99"
    function = "malloc"


class C99MemcmpTests(LibraryModelTest):
    library = "c99"
    function = "memcmp"


class C99MemcpyTests(LibraryModelTest):
    library = "c99"
    function = "memcpy"


class C99MemmoveTests(LibraryModelTest):
    library = "c99"
    function = "memmove"


class C99MemsetTests(LibraryModelTest):
    library = "c99"
    function = "memset"


class C99RandTests(NoArgLibraryModelTest):
    library = "c99"
    function = "rand"


class C99ReallocTests(NoArgLibraryModelTest):
    library = "c99"
    function = "realloc"


class C99SrandTests(NoArgLibraryModelTest):
    library = "c99"
    function = "srand"


class C99StrcatTests(LibraryModelTest):
    library = "c99"
    function = "strcat"


class C99StrchrTests(LibraryModelTest):
    library = "c99"
    function = "strchr"


class C99StrcmpTests(LibraryModelTest):
    library = "c99"
    function = "strcmp"


class C99StrcpyTests(LibraryModelTest):
    library = "c99"
    function = "strcpy"


class C99StrcspnTests(NoArgLibraryModelTest):
    library = "c99"
    function = "strcspn"


class C99StrerrorTests(NoArgLibraryModelTest):
    library = "c99"
    function = "strerror"


class C99StrlenTests(LibraryModelTest):
    library = "c99"
    function = "strlen"


class C99StrncmpTests(LibraryModelTest):
    library = "c99"
    function = "strncmp"


class C99StrncpyTests(LibraryModelTest):
    library = "c99"
    function = "strncpy"


class C99StrncatTests(LibraryModelTest):
    library = "c99"
    function = "strncat"


class C99StrpbrkTests(LibraryModelTest):
    library = "c99"
    function = "strpbrk"


class C99StrrchrTests(LibraryModelTest):
    library = "c99"
    function = "strrchr"


class C99StrspnTests(NoArgLibraryModelTest):
    library = "c99"
    function = "strspn"


class C99StrstrTests(NoArgLibraryModelTest):
    library = "c99"
    function = "strstr"


class C99StrtokTests(NoArgLibraryModelTest):
    library = "c99"
    function = "strtok"


class C99SystemTests(AbsLibraryModelTest):
    library = "c99"
    function = "system"

    def run_test(self, arch):
        _, stderr = self.command(
            f"python3 {self.library}/{self.function}/{self.function}.{arch}.py"
        )
        self.assertLineContainsStrings(stderr, "system(foobar);")


class C99SprintfTests(NoArgLibraryModelTest):
    library = "c99"
    function = "sprintf"


class C99SnprintfTests(NoArgLibraryModelTest):
    library = "c99"
    function = "snprintf"


class PrintLibraryModelTest(AbsLibraryModelTest):
    def run_test(self, arch):
        stdout, _ = self.command(
            f"python3 {self.library}/{self.function}/{self.function}.{arch}.py"
        )
        with open(
            f"{self.library}/{self.function}/{self.function}.{arch}.txt", "r"
        ) as f:
            expected = f.read()

        self.assertTrue("SUCCESS" in stdout)
        self.assertEqual(stdout, expected)


class C99FprintfTests(PrintLibraryModelTest):
    library = "c99"
    function = "fprintf"


class C99PrintfTests(PrintLibraryModelTest):
    library = "c99"
    function = "printf"


class C99SscanfTests(NoArgLibraryModelTest):
    library = "c99"
    function = "sscanf"


class ScanLibraryModelTest(AbsLibraryModelTest):
    def run_test(self, arch):
        _, _ = self.command(
            f"echo -n '' | python3 {self.library}/{self.function}/{self.function}.{arch}.py"
        )


class C99FscanfTests(ScanLibraryModelTest):
    library = "c99"
    function = "fscanf"


class C99ScanfTests(ScanLibraryModelTest):
    library = "c99"
    function = "scanf"


class C99FopenTests(NoArgLibraryModelTest):
    library = "c99"
    function = "fopen"


class C99FcloseTests(NoArgLibraryModelTest):
    library = "c99"
    function = "fclose"


class C99FgetcTests(OneArgLibraryModelTest):
    library = "c99"
    function = "fgetc"


class C99GetcTests(OneArgLibraryModelTest):
    library = "c99"
    function = "getc"


class C99GetcharTests(OneArgLibraryModelTest):
    library = "c99"
    function = "getchar"


class C99GetsTests(OneArgLibraryModelTest):
    library = "c99"
    function = "gets"


class C99FgetsTests(OneArgLibraryModelTest):
    library = "c99"
    function = "fgets"


class C99FflushTests(NoArgLibraryModelTest):
    library = "c99"
    function = "fflush"


class C99RemoveTests(NoArgLibraryModelTest):
    library = "c99"
    function = "remove"


class C99FputcTests(NoArgLibraryModelTest):
    library = "c99"
    function = "fputc"


class C99FputsTests(NoArgLibraryModelTest):
    library = "c99"
    function = "fputs"


class C99PutcTests(NoArgLibraryModelTest):
    library = "c99"
    function = "putc"


class C99PutsTests(NoArgLibraryModelTest):
    library = "c99"
    function = "puts"


class C99PutcharTests(NoArgLibraryModelTest):
    library = "c99"
    function = "putchar"


class C99FreadTests(OneArgLibraryModelTest):
    library = "c99"
    function = "fread"


class C99FwriteTests(NoArgLibraryModelTest):
    library = "c99"
    function = "fwrite"


class C99FtellTests(NoArgLibraryModelTest):
    library = "c99"
    function = "ftell"


class C99FseekTests(NoArgLibraryModelTest):
    library = "c99"
    function = "fseek"


class C99RewindTests(NoArgLibraryModelTest):
    library = "c99"
    function = "rewind"


class C99TmpfileTests(NoArgLibraryModelTest):
    library = "c99"
    function = "tmpfile"


class C99TmpnamTests(NoArgLibraryModelTest):
    library = "c99"
    function = "tmpnam"


class C99FeofTests(NoArgLibraryModelTest):
    library = "c99"
    function = "feof"


class C99ClearerrTests(NoArgLibraryModelTest):
    library = "c99"
    function = "clearerr"


class C99UngetcTests(NoArgLibraryModelTest):
    library = "c99"
    function = "ungetc"


class C99FgetposTests(NoArgLibraryModelTest):
    library = "c99"
    function = "fgetpos"


class C99FsetposTests(NoArgLibraryModelTest):
    library = "c99"
    function = "fsetpos"


class C99RenameTests(NoArgLibraryModelTest):
    library = "c99"
    function = "rename"


class C99ClockTests(NoArgLibraryModelTest):
    library = "c99"
    function = "clock"


class C99TimeTests(NoArgLibraryModelTest):
    library = "c99"
    function = "time"


class C99GmtimeTests(NoArgLibraryModelTest):
    library = "c99"
    function = "gmtime"


class C99LocaltimeTests(NoArgLibraryModelTest):
    library = "c99"
    function = "localtime"


class C99AsctimeTests(NoArgLibraryModelTest):
    library = "c99"
    function = "asctime"


class C99CtimeTests(NoArgLibraryModelTest):
    library = "c99"
    function = "ctime"


class C99DifftimeTests(NoArgLibraryModelTest):
    library = "c99"
    function = "difftime"


class C99MktimeTests(NoArgLibraryModelTest):
    library = "c99"
    function = "mktime"


class C99StrftimeTests(NoArgLibraryModelTest):
    library = "c99"
    function = "strftime"


class C99SignalTests(NoArgLibraryModelTest):
    library = "c99"
    function = "signal"


class POSIXBsdSignalTests(NoArgLibraryModelTest):
    library = "posix"
    function = "bsd_signal"


class POSIXPthreadSigmaskTests(NoArgLibraryModelTest):
    library = "posix"
    function = "pthread_sigmask"


class POSIXSigactionTests(NoArgLibraryModelTest):
    library = "posix"
    function = "sigaction"


class POSIXSigaddsetTests(NoArgLibraryModelTest):
    library = "posix"
    function = "sigaddset"


class POSIXSigdelsetTests(NoArgLibraryModelTest):
    library = "posix"
    function = "sigdelset"


class POSIXSigemptysetTests(NoArgLibraryModelTest):
    library = "posix"
    function = "sigemptyset"


class POSIXSigfillsetTests(NoArgLibraryModelTest):
    library = "posix"
    function = "sigfillset"


class POSIXSigpendingTests(NoArgLibraryModelTest):
    library = "posix"
    function = "sigpending"


class POSIXSigprocmaskTests(NoArgLibraryModelTest):
    library = "posix"
    function = "sigprocmask"


class POSIXBasenameTests(NoArgLibraryModelTest):
    library = "posix"
    function = "basename"


class POSIXDirnameTests(NoArgLibraryModelTest):
    library = "posix"
    function = "dirname"


class TraceExecutionTests(ScriptIntegrationTest):
    def test_trace_is_correct_no_heap(self):
        stdout, stderr = self.command("python3 trace_executor/test_trace_no_heap.py")
        self.assertLineContainsStrings(
            stdout, "Test result: trace_digest matches passed=True"
        )

    def test_trace_is_correct_1(self):
        stdout, stderr = self.command(
            "python3 trace_executor/test_trace_is_correct_1.py"
        )
        self.assertLineContainsStrings(
            stdout, "Test result: trace_digest matches passed=True"
        )

    def test_trace_is_correct_2(self):
        stdout, stderr = self.command(
            "python3 trace_executor/test_trace_is_correct_2.py"
        )
        self.assertLineContainsStrings(
            stdout, "Test result: trace_digest matches passed=True"
        )

    def test_trace_reproduces(self):
        stdout, stderr = self.command("python3 trace_executor/test_trace_reproduces.py")
        self.assertLineContainsStrings(stdout, "Test result: passed=True")

    def test_traces_different(self):
        stdout, stderr = self.command("python3 trace_executor/test_traces_different.py")
        self.assertLineContainsStrings(stdout, "Test result: passed=False")
        self.assertLineContainsStrings(stdout, "version1 DOES NOT matches version2")

    def test_branch_and_cmp_info(self):
        stdout, stderr = self.command(
            "python3 trace_executor/test_branch_and_cmp_info.py"
        )
        self.assertLineContainsStrings(
            stdout, "Test result: trace_digest matches passed=True"
        )
        self.assertLineContainsStrings(stdout, "EXPECTED   cmps match for pc=21a2")
        self.assertLineContainsStrings(
            stdout, "EXPECTED   immediates match for pc=21a2"
        )
        self.assertLineContainsStrings(stdout, "EXPECTED   cmps match for pc=21ac")
        self.assertLineContainsStrings(
            stdout, "EXPECTED   immediates match for pc=21ac"
        )
        self.assertLineContainsStrings(stdout, "EXPECTED   cmps match for pc=2236")
        self.assertLineContainsStrings(stdout, "EXPECTED   num_branches = 3")


class ColorizerTests(ScriptIntegrationTest):
    def test_colors_1(self):
        stdout, stderr = self.command("python3 colorizer/test_colorizer_1.py")
        self.assertLineContainsStrings(stdout, "EXPECTED  No unexpected results")

    def test_colors_2(self):
        stdout, stderr = self.command("python3 colorizer/test_colorizer_2.py")
        self.assertLineContainsStrings(stdout, "EXPECTED  No unexpected results")


class FsgsbaseTests(ScriptIntegrationTest):
    def test1(self):
        stdout, stderr = self.command("python fsgsbase/fsgsbase.amd64.py")
        self.assertLineContainsStrings(
            stdout,
            "Here's where in fs segment lsb of rax is: 40. ... which is correct.  Looks like fs:[0x28] address is working properly.",
        )
        self.assertLineContainsStrings(
            stdout,
            "Here's where in gs segment lsb of rbx is: 19. ... which is correct.  Looks like gs:[0x13] address is working properly.",
        )


class RTOSDemoTests(ScriptIntegrationTest):
    def _rtos_demo_dir(self):
        return os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "..", "use_cases", "rtos_demo"
        )

    def _fuzz_inputs_dir(self):
        return os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "rtos_demo", "fuzz_inputs"
        )

    def run_test(self, script: str) -> str:
        stdout, _ = self.command(f"python3 {script}", cwd=self._rtos_demo_dir())
        return stdout

    def test_rtos_run(self):
        stdout = self.run_test("rtos_0_run.py")
        self.assertLineContainsStrings(stdout, "Buffer: b'ABCDEFGHIJKLMNOP'")

    def test_rtos_fuzz(self):
        stdout, _ = self.command(
            f"afl-showmap -C -t 10000 -U -m none -i {self._fuzz_inputs_dir()} -o /dev/stdout -- python3 rtos_1_fuzz.py @@",
            stdin="testcase",
            cwd=self._rtos_demo_dir(),
        )
        for line in [
            "002456:16",
            "011100:1",
            "013130:1",
            "015900:1",
            "024604:32",
            "025020:16",
            "037869:16",
            "040576:1",
            "040899:1",
            "041903:16",
            "042135:1",
            "047722:32",
            "052842:1",
            "058902:1",
            "062301:1",
        ]:
            self.assertLineContainsStrings(stdout, line)

    def test_rtos_analysis(self):
        stdout = self.run_test("rtos_2_analyze.py")
        self.assertLineContainsStrings(stdout, "r4: 0xf")
        self.assertLineContainsStrings(stdout, "r8: <BV32 0#24 .. input_buffer[7:0]>")

    def test_rtos_find_lr(self):
        stdout = self.run_test("rtos_3_find_lr.py")
        self.assertLineContainsStrings(stdout, ".. Reverse(lr)>")

    def test_rtos_exploit(self):
        stdout = self.run_test("rtos_4_exploit.py")
        self.assertLineContainsStrings(stdout, "PC: 0x1027c4")
        self.assertLineContainsStrings(stdout, "Reached stop_udp: True")


class ThumbTests(ScriptIntegrationTest):
    """
    Test that ARM32 binaries with mixed ARM/Thumb code are
    executed and disassembled properly.
    """

    def _check_output(
        self,
        stdout: str,
        stderr: str,
        archs: list[smallworld.platforms.platforms.Architecture],
    ):
        for arch in archs:
            # check program result for step starting in ARM mode
            self.assertLineContainsStrings(stdout, f"STEP_{arch.name}=0x6")
            # check program result for step starting in Thumb mode
            self.assertLineContainsStrings(stdout, f"STEP_{arch.name}=0x4")
            # check disassembly
            self.assertLineContainsStrings(
                stderr, "single step at 0x1000: <CsInsn 0x1000 [0110a0e3]: mov r1, #1>"
            )
            self.assertLineContainsStrings(
                stderr, "single step at 0x1010: <CsInsn 0x1010 [0121]: movs r1, #1>"
            )
            self.assertLineContainsStrings(
                stderr, "single step at 0x101c: <CsInsn 0x101c [0110a0e3]: mov r1, #1>"
            )
            # check program result for step_block starting in ARM mode
            self.assertLineContainsStrings(stdout, f"BLOCK_{arch.name}=0x6")
            # check program result for step_block starting in Thumb mode
            self.assertLineContainsStrings(stdout, f"BLOCK_{arch.name}=0x4")
            # check disassembly for step_block
            self.assertLineContainsStrings(
                stderr, "step block at 0x1000: <CsInsn 0x1000 [0110a0e3]: mov r1, #1>"
            )
            self.assertLineContainsStrings(
                stderr, "step block at 0x1010: <CsInsn 0x1010 [0121]: movs r1, #1>"
            )
            self.assertLineContainsStrings(
                stderr, "step block at 0x101c: <CsInsn 0x101c [0110a0e3]: mov r1, #1>"
            )
            # check program result for run starting in ARM mode
            self.assertLineContainsStrings(stdout, f"RUN_{arch.name}=0x6")
            # check program result for run starting in Thumb mode
            self.assertLineContainsStrings(stdout, f"RUN_{arch.name}=0x4")
            # check ISA persistance between emulators
            self.assertLineContainsStrings(stdout, f"PERSIST_THUMB_{arch.name}=0x4")
            # check program mode pre-execution, starting in Thumb
            self.assertLineContainsStrings(stdout, f"GET_THUMB_PRE1_{arch.name}=True")
            # check program mode post-execution, ending in ARM
            self.assertLineContainsStrings(stdout, f"GET_THUMB_POST1_{arch.name}=False")
            # check program mode pre-execution, starting in ARM
            self.assertLineContainsStrings(stdout, f"GET_THUMB_PRE2_{arch.name}=False")
            # check program mode post-execution, ending in Thumb
            self.assertLineContainsStrings(stdout, f"GET_THUMB_POST2_{arch.name}=True")

    def test_thumb_armhf(self):
        archs = [
            smallworld.platforms.Architecture.ARM_V7A,
            smallworld.platforms.Architecture.ARM_V7M,
            smallworld.platforms.Architecture.ARM_V7R,
        ]
        stdout, stderr = self.command("python3 thumb/thumb.armhf.py")
        self._check_output(stdout, stderr, archs)

    def test_thumb_armel(self):
        archs = [
            smallworld.platforms.Architecture.ARM_V5T,
            smallworld.platforms.Architecture.ARM_V6M,
        ]
        stdout, stderr = self.command("python3 thumb/thumb.armel.py")
        self._check_output(stdout, stderr, archs)


class CheckedDoubleFreeTests(ScriptIntegrationTest):
    def run_test(self, kind):
        self.command(f"python3 checked_heap/double_free/double_free.{kind}.py")

    def test_aarch64_unicorn(self):
        self.run_test("aarch64")

    def test_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_aarch64_ghidra(self):
        self.run_test("aarch64.pcode")

    def test_amd64_unicorn(self):
        self.run_test("amd64")

    def test_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_amd64_ghidra(self):
        self.run_test("amd64.pcode")

    def test_armel_unicorn(self):
        self.run_test("armel")

    def test_armel_angr(self):
        self.run_test("armel.angr")

    def test_armel_panda(self):
        self.run_test("armel.panda")

    def test_armel_ghidra(self):
        self.run_test("armel.pcode")

    def test_armhf_unicorn(self):
        self.run_test("armhf")

    def test_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_armhf_ghidra(self):
        self.run_test("armhf.pcode")

    def test_i386_unicorn(self):
        self.run_test("i386")

    def test_i386_angr(self):
        self.run_test("i386.angr")

    def test_i386_panda(self):
        self.run_test("i386.panda")

    def test_i386_ghidra(self):
        self.run_test("i386.pcode")

    def test_mips_unicorn(self):
        self.run_test("mips")

    def test_mips_angr(self):
        self.run_test("mips.angr")

    def test_mips_panda(self):
        self.run_test("mips.panda")

    def test_mips_ghidra(self):
        self.run_test("mips.pcode")

    def test_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_mips64_ghidra(self):
        self.run_test("mips64.pcode")

    def test_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_mips64el_ghidra(self):
        self.run_test("mips64el.pcode")

    def test_mipsel_unicorn(self):
        self.run_test("mipsel")

    def test_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_mipsel_ghidra(self):
        self.run_test("mipsel.pcode")

    def test_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_ppc_ghidra(self):
        self.run_test("ppc.pcode")

    def test_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_riscv64_ghidra(self):
        self.run_test("riscv64.pcode")


class CheckedReadTests(ScriptIntegrationTest):
    def run_test(self, kind):
        self.command(f"python3 checked_heap/read/read.{kind}.py")

    def test_aarch64_unicorn(self):
        self.run_test("aarch64")

    def test_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_aarch64_ghidra(self):
        self.run_test("aarch64.pcode")

    def test_amd64_unicorn(self):
        self.run_test("amd64")

    def test_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_amd64_ghidra(self):
        self.run_test("amd64.pcode")

    def test_armel_unicorn(self):
        self.run_test("armel")

    def test_armel_angr(self):
        self.run_test("armel.angr")

    def test_armel_panda(self):
        self.run_test("armel.panda")

    def test_armel_ghidra(self):
        self.run_test("armel.pcode")

    def test_armhf_unicorn(self):
        self.run_test("armhf")

    def test_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_armhf_ghidra(self):
        self.run_test("armhf.pcode")

    def test_i386_unicorn(self):
        self.run_test("i386")

    def test_i386_angr(self):
        self.run_test("i386.angr")

    def test_i386_panda(self):
        self.run_test("i386.panda")

    def test_i386_ghidra(self):
        self.run_test("i386.pcode")

    def test_mips_unicorn(self):
        self.run_test("mips")

    def test_mips_angr(self):
        self.run_test("mips.angr")

    def test_mips_panda(self):
        self.run_test("mips.panda")

    def test_mips_ghidra(self):
        self.run_test("mips.pcode")

    def test_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_mips64_ghidra(self):
        self.run_test("mips64.pcode")

    def test_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_mips64el_ghidra(self):
        self.run_test("mips64el.pcode")

    def test_mipsel_unicorn(self):
        self.run_test("mipsel")

    def test_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_mipsel_ghidra(self):
        self.run_test("mipsel.pcode")

    def test_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_ppc_ghidra(self):
        self.run_test("ppc.pcode")

    def test_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_riscv64_ghidra(self):
        self.run_test("riscv64.pcode")


class CheckedWriteTests(ScriptIntegrationTest):
    def run_test(self, kind):
        self.command(f"python3 checked_heap/write/write.{kind}.py")

    def test_aarch64_unicorn(self):
        self.run_test("aarch64")

    def test_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_aarch64_ghidra(self):
        self.run_test("aarch64.pcode")

    def test_amd64_unicorn(self):
        self.run_test("amd64")

    def test_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_amd64_ghidra(self):
        self.run_test("amd64.pcode")

    def test_armel_unicorn(self):
        self.run_test("armel")

    def test_armel_angr(self):
        self.run_test("armel.angr")

    def test_armel_panda(self):
        self.run_test("armel.panda")

    def test_armel_ghidra(self):
        self.run_test("armel.pcode")

    def test_armhf_unicorn(self):
        self.run_test("armhf")

    def test_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_armhf_ghidra(self):
        self.run_test("armhf.pcode")

    def test_i386_unicorn(self):
        self.run_test("i386")

    def test_i386_angr(self):
        self.run_test("i386.angr")

    def test_i386_panda(self):
        self.run_test("i386.panda")

    def test_i386_ghidra(self):
        self.run_test("i386.pcode")

    def test_mips_unicorn(self):
        self.run_test("mips")

    def test_mips_angr(self):
        self.run_test("mips.angr")

    def test_mips_panda(self):
        self.run_test("mips.panda")

    def test_mips_ghidra(self):
        self.run_test("mips.pcode")

    def test_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_mips64_ghidra(self):
        self.run_test("mips64.pcode")

    def test_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_mips64el_ghidra(self):
        self.run_test("mips64el.pcode")

    def test_mipsel_unicorn(self):
        self.run_test("mipsel")

    def test_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_mipsel_ghidra(self):
        self.run_test("mipsel.pcode")

    def test_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_ppc_ghidra(self):
        self.run_test("ppc.pcode")

    def test_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_riscv64_ghidra(self):
        self.run_test("riscv64.pcode")


class CheckedUAFTests(ScriptIntegrationTest):
    def run_test(self, kind):
        self.command(f"python3 checked_heap/uaf/uaf.{kind}.py")

    def test_aarch64_unicorn(self):
        self.run_test("aarch64")

    def test_aarch64_angr(self):
        self.run_test("aarch64.angr")

    def test_aarch64_panda(self):
        self.run_test("aarch64.panda")

    def test_aarch64_ghidra(self):
        self.run_test("aarch64.pcode")

    def test_amd64_unicorn(self):
        self.run_test("amd64")

    def test_amd64_angr(self):
        self.run_test("amd64.angr")

    def test_amd64_panda(self):
        self.run_test("amd64.panda")

    def test_amd64_ghidra(self):
        self.run_test("amd64.pcode")

    def test_armel_unicorn(self):
        self.run_test("armel")

    def test_armel_angr(self):
        self.run_test("armel.angr")

    def test_armel_panda(self):
        self.run_test("armel.panda")

    def test_armel_ghidra(self):
        self.run_test("armel.pcode")

    def test_armhf_unicorn(self):
        self.run_test("armhf")

    def test_armhf_angr(self):
        self.run_test("armhf.angr")

    def test_armhf_panda(self):
        self.run_test("armhf.panda")

    def test_armhf_ghidra(self):
        self.run_test("armhf.pcode")

    def test_i386_unicorn(self):
        self.run_test("i386")

    def test_i386_angr(self):
        self.run_test("i386.angr")

    def test_i386_panda(self):
        self.run_test("i386.panda")

    def test_i386_ghidra(self):
        self.run_test("i386.pcode")

    def test_mips_unicorn(self):
        self.run_test("mips")

    def test_mips_angr(self):
        self.run_test("mips.angr")

    def test_mips_panda(self):
        self.run_test("mips.panda")

    def test_mips_ghidra(self):
        self.run_test("mips.pcode")

    def test_mips64_angr(self):
        self.run_test("mips64.angr")

    def test_mips64_panda(self):
        self.run_test("mips64.panda")

    def test_mips64_ghidra(self):
        self.run_test("mips64.pcode")

    def test_mips64el_angr(self):
        self.run_test("mips64el.angr")

    def test_mips64el_panda(self):
        self.run_test("mips64el.panda")

    def test_mips64el_ghidra(self):
        self.run_test("mips64el.pcode")

    def test_mipsel_unicorn(self):
        self.run_test("mipsel")

    def test_mipsel_angr(self):
        self.run_test("mipsel.angr")

    def test_mipsel_panda(self):
        self.run_test("mipsel.panda")

    def test_mipsel_ghidra(self):
        self.run_test("mipsel.pcode")

    def test_ppc_angr(self):
        self.run_test("ppc.angr")

    def test_ppc_panda(self):
        self.run_test("ppc.panda")

    def test_ppc_ghidra(self):
        self.run_test("ppc.pcode")

    def test_riscv64_angr(self):
        self.run_test("riscv64.angr")

    def test_riscv64_ghidra(self):
        self.run_test("riscv64.pcode")


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
