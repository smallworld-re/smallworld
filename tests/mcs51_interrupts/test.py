"""Unit tests for the 8051's interrupt logic in smallworld.platforms.defs.mcs51.

The mcs51_diff scenario's interrupts program checks the backends against
ucsim_51; these cover the rules it cannot, where ucsim departs from the 8051
manual, and the logic's bookkeeping directly, and the C8051F33x's sources
and MCS51Device, which the mcs51_sdcc scenario's interrupts program runs.
"""

import typing
import unittest

from smallworld import exceptions
from smallworld.platforms.defs.mcs51 import (
    MCS51_IE_EA,
    MCS51_OPCODE_RETI,
    MCS51_SFR_BASE,
    MCS51_SFR_EIE1,
    MCS51_SFR_EIP1,
    MCS51_SFR_IE,
    MCS51_SFR_IP,
    MCS51_SFR_T2CON,
    MCS51_SFR_TCON,
    C8051F33xInterrupt,
    MCS51Interrupt,
    MCS51InterruptState,
    mcs51_interrupt_sfrs,
    mcs51_interrupt_to_take,
    mcs51_interrupts,
    mcs51_raise_interrupt,
    mcs51_service_interrupts,
)
from smallworld.state.cpus import MCS51Device

NOP = 0x00


def sfrs(**values: int) -> typing.Callable[[int], int]:
    named = {"ie": MCS51_SFR_IE, "ip": MCS51_SFR_IP, "tcon": MCS51_SFR_TCON}
    memory = {named[name]: value for name, value in values.items()}
    return lambda address: memory.get(address, 0)


TF0 = MCS51Interrupt.TIMER0.request
TF1 = MCS51Interrupt.TIMER1.request
IE0 = MCS51Interrupt.EXTERNAL0.request
ALL = MCS51_IE_EA | 0x3F


class MCS51InterruptChoiceTests(unittest.TestCase):
    def test_nothing_without_ea(self):
        self.assertIsNone(mcs51_interrupt_to_take(sfrs(ie=0x3F, tcon=TF0), ()))

    def test_nothing_without_its_enable_bit(self):
        self.assertIsNone(mcs51_interrupt_to_take(sfrs(ie=MCS51_IE_EA, tcon=TF0), ()))

    def test_enabled_request_is_taken(self):
        self.assertEqual(
            mcs51_interrupt_to_take(sfrs(ie=ALL, tcon=TF0), ()),
            (MCS51Interrupt.TIMER0, 0),
        )

    def test_polling_order_within_a_level(self):
        self.assertEqual(
            mcs51_interrupt_to_take(sfrs(ie=ALL, tcon=TF1 | IE0), ()),
            (MCS51Interrupt.EXTERNAL0, 0),
        )

    def test_priority_beats_polling_order(self):
        # The 8051 manual: of simultaneous requests, the higher priority is
        # serviced.  ucsim_51 takes IE0 first here.
        ip = MCS51Interrupt.TIMER1.enable
        self.assertEqual(
            mcs51_interrupt_to_take(sfrs(ie=ALL, ip=ip, tcon=TF1 | IE0), ()),
            (MCS51Interrupt.TIMER1, 1),
        )

    def test_in_service_level_blocks_its_own_level(self):
        self.assertIsNone(mcs51_interrupt_to_take(sfrs(ie=ALL, tcon=TF0), (0,)))

    def test_high_priority_nests_over_low(self):
        ip = MCS51Interrupt.TIMER1.enable
        self.assertEqual(
            mcs51_interrupt_to_take(sfrs(ie=ALL, ip=ip, tcon=TF1), (0,)),
            (MCS51Interrupt.TIMER1, 1),
        )

    def test_nothing_nests_over_high(self):
        ip = 0x3F
        self.assertIsNone(mcs51_interrupt_to_take(sfrs(ie=ALL, ip=ip, tcon=TF1), (1,)))


class MCS51InterruptServiceTests(unittest.TestCase):
    def service(self, state, read_sfr, code=NOP):
        return mcs51_service_interrupts(state, 0x1000, read_sfr, lambda _: code)

    def test_taking_records_the_level_and_the_vector_instruction(self):
        ljmp = 0x02
        state, source = self.service(
            MCS51InterruptState(), sfrs(ie=ALL, tcon=TF0), code=ljmp
        )
        self.assertIs(source, MCS51Interrupt.TIMER0)
        self.assertEqual(state.in_service, (0,))
        self.assertEqual(state.previous, (ljmp, (ALL, 0)))

    def test_reti_ends_service_and_holds_one_instruction(self):
        read_sfr = sfrs(ie=ALL, tcon=TF0)
        state = MCS51InterruptState((0,), (MCS51_OPCODE_RETI, (ALL, 0)))
        state, source = self.service(state, read_sfr)
        self.assertIsNone(source)
        self.assertEqual(state.in_service, ())
        state, source = self.service(state, read_sfr)
        self.assertIs(source, MCS51Interrupt.TIMER0)

    def test_writing_ie_or_ip_holds_one_instruction(self):
        for previous in ((NOP, (0, 0)), (NOP, (ALL, 0x02))):
            state = MCS51InterruptState((), previous)
            state, source = self.service(state, sfrs(ie=ALL, tcon=TF0))
            self.assertIsNone(source, previous)
            _, source = self.service(state, sfrs(ie=ALL, tcon=TF0))
            self.assertIs(source, MCS51Interrupt.TIMER0, previous)

    def test_plain_ret_stays_in_service(self):
        ret = 0x22
        state = MCS51InterruptState((0,), (ret, (ALL, 0)))
        state, source = self.service(state, sfrs(ie=ALL, tcon=TF0))
        self.assertIsNone(source)
        self.assertEqual(state.in_service, (0,))


class MCS51RaiseInterruptTests(unittest.TestCase):
    class Memory:
        def __init__(self):
            self.bytes: typing.Dict[int, int] = {}

        def read_memory(self, address: int, size: int) -> bytes:
            return bytes(self.bytes.get(address + i, 0) for i in range(size))

        def write_memory(self, address: int, data: bytes) -> None:
            for i, byte in enumerate(data):
                self.bytes[address + i] = byte

    def test_sets_the_request_flag_and_keeps_the_others(self):
        emulator = self.Memory()
        emulator.bytes[MCS51_SFR_BASE + MCS51_SFR_TCON] = 0x10
        mcs51_raise_interrupt(emulator, MCS51Interrupt.TIMER0)
        self.assertEqual(emulator.bytes[MCS51_SFR_BASE + MCS51_SFR_TCON], 0x30)

    def test_serial_requests_receive(self):
        emulator = self.Memory()
        mcs51_raise_interrupt(emulator, MCS51Interrupt.SERIAL)
        self.assertEqual(emulator.bytes[MCS51_SFR_BASE + 0x98], 0x01)


def sfr_values(values: typing.Dict[int, int]) -> typing.Callable[[int], int]:
    return lambda address: values.get(address, 0)


# C8051F33x SFRs and bits, from its data sheet.
SPI0CN, SPIF = 0xF8, 0x80
SMB0CN, SI = 0xC0, 0x01
ESPI0, ESMB0 = 0x40, 0x01
TF2L, TF2LEN = 0x40, 0x20
PCA0CN, PCA0MD, PCA0CPM1, CF, CCF1, ECCF = 0xD8, 0xD9, 0xDB, 0x80, 0x02, 0x01


class C8051F33xInterruptTests(unittest.TestCase):
    def take(self, values: typing.Dict[int, int], in_service=()):
        return mcs51_interrupt_to_take(
            sfr_values(values), in_service, C8051F33xInterrupt
        )

    def test_extended_sources_need_their_eie1_bit(self):
        values = {MCS51_SFR_IE: MCS51_IE_EA, SMB0CN: SI}
        self.assertIsNone(self.take(values))
        values[MCS51_SFR_EIE1] = ESMB0
        self.assertEqual(self.take(values), (C8051F33xInterrupt.SMBUS0, 0))

    def test_ie_sources_poll_before_eie1_sources(self):
        values = {
            MCS51_SFR_IE: MCS51_IE_EA | ESPI0,
            MCS51_SFR_EIE1: ESMB0,
            SPI0CN: SPIF,
            SMB0CN: SI,
        }
        self.assertEqual(self.take(values), (C8051F33xInterrupt.SPI0, 0))

    def test_eip1_priority_beats_polling_order(self):
        values = {
            MCS51_SFR_IE: MCS51_IE_EA | ESPI0,
            MCS51_SFR_EIE1: ESMB0,
            MCS51_SFR_EIP1: ESMB0,
            SPI0CN: SPIF,
            SMB0CN: SI,
        }
        self.assertEqual(self.take(values), (C8051F33xInterrupt.SMBUS0, 1))
        self.assertIsNone(self.take(values, in_service=(1,)))

    def test_timer2_low_byte_flag_needs_tf2len(self):
        enable = C8051F33xInterrupt.TIMER2.enable
        values = {MCS51_SFR_IE: MCS51_IE_EA | enable, MCS51_SFR_T2CON: TF2L}
        self.assertIsNone(self.take(values))
        values[MCS51_SFR_T2CON] = TF2L | TF2LEN
        self.assertEqual(self.take(values), (C8051F33xInterrupt.TIMER2, 0))

    def test_pca_flags_need_their_own_enables(self):
        enable = C8051F33xInterrupt.PCA0.enable
        values = {MCS51_SFR_IE: MCS51_IE_EA, MCS51_SFR_EIE1: enable}
        values[PCA0CN] = CCF1
        self.assertIsNone(self.take(values))
        values[PCA0CPM1] = ECCF
        self.assertEqual(self.take(values), (C8051F33xInterrupt.PCA0, 0))
        values[PCA0CN] = CF
        self.assertIsNone(self.take(values))
        values[PCA0MD] = 0x01  # ECF
        self.assertEqual(self.take(values), (C8051F33xInterrupt.PCA0, 0))

    def test_writing_eie1_holds_one_instruction(self):
        values = {
            MCS51_SFR_IE: MCS51_IE_EA,
            MCS51_SFR_EIE1: ESMB0,
            SMB0CN: SI,
        }
        # IE, IP, EIE1 and EIP1, before an instruction that enabled SMBus0.
        state = MCS51InterruptState((), (NOP, (MCS51_IE_EA, 0, 0, 0)))

        def service(state):
            return mcs51_service_interrupts(
                state,
                0x1000,
                sfr_values(values),
                lambda _: NOP,
                sources=C8051F33xInterrupt,
            )

        state, source = service(state)
        self.assertIsNone(source)
        _, source = service(state)
        self.assertIs(source, C8051F33xInterrupt.SMBUS0)

    def test_the_sfrs_interrupts_depend_on(self):
        self.assertEqual(
            mcs51_interrupt_sfrs(MCS51Interrupt), {0x88, 0x98, 0xA8, 0xB8, 0xC8}
        )
        sfrs = mcs51_interrupt_sfrs(C8051F33xInterrupt)
        self.assertTrue(
            {MCS51_SFR_EIE1, MCS51_SFR_EIP1, PCA0MD, PCA0CPM1, 0x9D} <= sfrs
        )


class MCS51DeviceTests(unittest.TestCase):
    def test_lookup_by_part_number(self):
        for device in ("C8051F330", "C8051F335", "c8051f331-gm"):
            with self.subTest(device=device):
                self.assertIs(mcs51_interrupts(device), C8051F33xInterrupt)
        device = MCS51Device("C8051F330")
        self.assertEqual(device.xpage_sfr, 0xAA)
        self.assertIs(device.interrupts, C8051F33xInterrupt)

    def test_devices_without_an_interrupt_table_take_the_8052s(self):
        # The C8051F336-F339 have a data sheet, and interrupts, of their own.
        for device, xpage_sfr in (("C8051F336", 0xAA), ("C8051F020", 0xAF)):
            with self.subTest(device=device):
                with self.assertLogs("smallworld.state.cpus.mcs51", "WARNING"):
                    mcs51_device = MCS51Device(device)
                self.assertEqual(mcs51_device.xpage_sfr, xpage_sfr)
                self.assertIs(mcs51_device.interrupts, MCS51Interrupt)

    def test_devices_without_a_paging_sfr_are_refused(self):
        for device in ("C8051F300", "8051"):
            with self.subTest(device=device):
                with self.assertRaises(ValueError):
                    MCS51Device(device)

    def test_apply_sets_the_paging_sfr_and_interrupts(self):
        class Emulator:
            def __init__(self):
                self.registers: typing.Dict[str, int] = {}
                self.machdef = self
                self.sources = None

            def write_register(self, name: str, value: int) -> None:
                self.registers[name] = value

            def set_interrupt_sources(self, emulator, sources) -> None:
                self.sources = sources

        for device, xpage_sfr, sources in (
            ("C8051F330", 0xAA, C8051F33xInterrupt),
            ("C8051F040", 0xA2, MCS51Interrupt),
        ):
            with self.subTest(device=device):
                emulator = Emulator()
                MCS51Device(device).apply(emulator)
                self.assertEqual(emulator.registers, {"xpage_sfr": xpage_sfr})
                self.assertIs(emulator.sources, sources)

    def test_emulators_that_cannot_take_its_interrupts_are_refused(self):
        class Emulator:
            def write_register(self, name: str, value: int) -> None:
                pass

        with self.assertRaises(exceptions.ConfigurationError):
            MCS51Device("C8051F330").apply(Emulator())


if __name__ == "__main__":
    unittest.main()
