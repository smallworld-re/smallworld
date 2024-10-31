import copy
import logging

from unicorn import unicorn_const

from ... import emulators, exceptions, hinting, instructions, state
from .. import analysis

logger = logging.getLogger(__name__)
hinter = hinting.get_hinter(__name__)


class PointerFinder(analysis.Analysis):
    """A simple analysis that logs when a register is used as a pointer.

    Arguments:
        num_instructions: The number of instructions to execute.
    """

    def __init__(self, *args, num_instructions: int = 10, **kwargs):
        super().__init__(*args, **kwargs)
        self.num_instructions = num_instructions

    name = "pointer-finder"
    description = ""
    version = "0.0.1"

    def find_the_pointer(self, cs_instruction, write):
        i = instructions.Instruction.from_capstone(cs_instruction)
        p = None
        if write:
            for w in i.writes:
                if type(w) is instructions.BSIDMemoryReferenceOperand:
                    p = w
                    break
        else:
            for r in i.reads:
                if type(r) is instructions.BSIDMemoryReferenceOperand:
                    p = r
                    break

        assert p, "we can't find the pointer"
        hint = hinting.PointerHint(message="Pointer Found", instruction=i, pointer=r)
        hinter.info(hint)

    def run(self, state: state.Machine) -> None:
        machine = copy.deepcopy(state)
        cpu = machine.get_cpu()
        emulator = emulators.UnicornEmulator(cpu.platform)
        machine.apply(emulator)

        def hook_valid_access(uc, access, address, size, value, user_data):
            instruction = emulator.current_instruction()
            if access == unicorn_const.UC_MEM_WRITE:
                self.find_the_pointer(instruction, True)
            else:
                self.find_the_pointer(instruction, False)

        def hook_invalid_access(uc, access, address, size, value, user_data):
            instruction = emulator.current_instruction()
            if access == unicorn_const.UC_MEM_WRITE_UNMAPPED:
                self.find_the_pointer(instruction, True)
            else:
                self.find_the_pointer(instruction, False)
            return False

        emulator.engine.hook_add(
            unicorn_const.UC_HOOK_MEM_WRITE | unicorn_const.UC_HOOK_MEM_READ,
            hook_valid_access,
        )
        emulator.engine.hook_add(
            unicorn_const.UC_HOOK_MEM_READ_UNMAPPED
            | unicorn_const.UC_HOOK_MEM_WRITE_UNMAPPED,
            hook_invalid_access,
        )

        for i in range(self.num_instructions):
            try:
                emulator.step()
            except exceptions.EmulationStop:
                break
            except exceptions.EmulationError as e:
                exhint = hinting.EmulationException(
                    message="Emulation single step raised an exception",
                    pc=emulator.current_instruction().address,
                    instruction_num=i,
                    exception=str(e),
                )
                hinter.info(exhint)
                break
