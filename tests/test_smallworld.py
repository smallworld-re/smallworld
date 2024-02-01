import itertools
import logging
import random
import unittest

from smallworld import cpus, executor, hinting, initializer, state, utils

utils.setup_logging(level=logging.INFO)
utils.setup_hinting(verbose=True, stream=True, file=None)


class TestSmallworld(unittest.TestCase):
    def check_input_hints(self, hints, input_name: str, pc: int) -> None:
        """Checks to see if we are hinting that something is an input

        Arguments:
            hints: the collection of hints generated by some analyses.
            input_name (str): the name of the input (such as 'rdi')
            pc (int): the program counter where is input is detected

        Returns:
            None
        """

        found_input = False
        for i in itertools.chain(hints.records):
            h = i.msg
            if type(h) is hinting.InputUseHint:
                if h.input_register.lower() == input_name.lower() and h.pc == pc:
                    found_input = True
                    break

        self.assertTrue(
            found_input,
            f"We know that {input_name} is an input to the function at pc {pc}",
        )

    def analyze_bin(self, cpu: state.CPU, code: executor.Code):
        """Runs all of the analyses and returns the hints generated

        Arguments:
            cpu (state.CPU): the cpu state to analyze
            code (executor.Code): the code to analyze

        Returns:
            A collection of hints from all of the analyses
        """
        zero = initializer.ZeroInitializer()
        cpu.initialize(zero)
        hinter = hinting.getHinter()
        with self.assertLogs(logger=hinter, level="INFO") as hints:
            utils.analyze(code, cpu)
        return hints

    def check_return(self, state, final_value: int) -> None:
        """Checks to see if the return value matchs a given value

        Arguments:
            state: the final cpu state
            final_value (int): the known good return value
        Returns:
            None
        """
        self.assertEqual(
            state.eax.get(), final_value, "Emulation returns the correct value"
        )

    def test_square(self):
        """Tests that the square example functions as expected

        Arguments:
            None
        Returns:
            None
        """
        cpu = cpus.AMD64CPUState()
        code = executor.Code.from_filepath("square.bin", base=0x1000, entry=0x1000)

        hints = self.analyze_bin(cpu, code)
        self.check_input_hints(hints, "edi", 0x1000)
        input_value = random.randint(1, 100)
        cpu.edi.set(input_value)
        self.assertEqual(input_value, cpu.edi.get(), "Our input value is being stored")
        final_state = utils.emulate(code, cpu)
        self.check_return(final_state, input_value * input_value)


if __name__ == "__main__":
    unittest.main()
