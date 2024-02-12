import os
import re
import subprocess
import typing
import unittest


class ScriptIntegrationTest(unittest.TestCase):
    def command(self, cmd: str) -> typing.Tuple[str, str]:
        """Run the given command and return the output.

        Arguments:
            cmd: The command to run.

        Returns:
            The `(stdout, stderr)` of the process as strings.
        """

        cwd = os.path.abspath(os.path.dirname(__file__))

        process = subprocess.run(
            cmd,
            cwd=cwd,
            shell=True,
            check=True,
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
            raise AssertionError(f"string does not contain `{match}`")

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

        raise AssertionError(f"no line in string contains all of `{matches}`")


class SquareTests(ScriptIntegrationTest):
    def test_square_0(self):
        _, stderr = self.command("python square_0.py")

        self.assertLineContains(stderr, "edi", "InputUseHint")

    def test_square_1(self):
        def test_output(number):
            stdout, _ = self.command(f"python square_1.py {number}")

            self.assertContains(stdout, hex(number**2))

        test_output(5)
        test_output(1337)
        test_output(65535)


if __name__ == "__main__":
    unittest.main()
