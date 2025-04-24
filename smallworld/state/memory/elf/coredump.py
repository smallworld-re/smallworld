import logging
import typing

import lief

from ....exceptions import ConfigurationError
from ....platforms import Platform
from ....state.cpus import CPU
from .elf import ElfExecutable
from .register_state import RegisterState

log = logging.getLogger(__name__)


class ElfCoreFile(ElfExecutable):
    """
    Extended loader to handle core-dump (ET_CORE) ELF files.
    """

    def __init__(
        self,
        file: typing.BinaryIO,
        platform: typing.Optional[Platform] = None,
        ignore_platform: bool = False,
        user_base: typing.Optional[int] = None,
        page_size: int = 0x1000,
    ):
        super().__init__(
            file=file,
            platform=platform,
            ignore_platform=ignore_platform,
            user_base=user_base,
            page_size=page_size,
        )

        file.seek(0)
        raw_data = file.read()
        parsed_elf = lief.ELF.parse(list(raw_data))

        if parsed_elf is None or parsed_elf.header.file_type != lief.ELF.E_TYPE.CORE:
            raise ConfigurationError("This file is not an ELF core dump (ET_CORE).")

        self.register_states: typing.Optional[RegisterState] = None

        for note in parsed_elf.notes:
            if isinstance(note, lief.ELF.CorePrStatus):
                arch_enum = note.architecture
                reg_values = note.register_values
                pc_val = note.pc or 0
                sp_val = note.sp or 0

                status = getattr(note.status, "si_status", 0)

                if platform is None:
                    raise ConfigurationError("Platform must be provided for core dumps")

                cpu = CPU.for_platform(platform)
                reg_names = cpu.get_general_purpose_registers()

                named_regs = {
                    name: val
                    for name, val in zip(reg_names, reg_values)
                    if name not in ("sp", "pc", "lr")
                }

                self.register_states = RegisterState(
                    registers=named_regs,
                    pc=pc_val,
                    sp=sp_val,
                    status=status,
                    arch=str(arch_enum),
                )
                break

    def load_core_registers_into_cpu(reg_state, cpu):
        """
        Given a RegisterState (with .pc, .sp, .r0, etc.) and a smallworld CPU,
        set each register on the CPU if it exists.
        """
        cpu.pc.set(reg_state.pc)
        cpu.sp.set(reg_state.sp)

        for reg_name, reg_val in reg_state._registers.items():
            reg_name_lower = reg_name.lower()
            if hasattr(cpu, reg_name_lower):
                getattr(cpu, reg_name_lower).set(reg_val)
