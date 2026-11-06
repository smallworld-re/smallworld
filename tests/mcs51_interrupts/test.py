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
    MCS51_C8051F04X_SFR_PAGING,
    MCS51_C8051F12X_SFR_PAGING,
    MCS51_C8051F33X_FLASH,
    MCS51_C8051F36X_SFR_PAGING,
    MCS51_CODE_BASE,
    MCS51_FLKEY_DISABLED,
    MCS51_FLKEY_FIRST_KEY,
    MCS51_FLKEY_LOCKED,
    MCS51_FLKEY_UNLOCKED,
    MCS51_IDATA_BASE,
    MCS51_IE_EA,
    MCS51_OPCODE_RETI,
    MCS51_PSCTL_PSEE,
    MCS51_PSCTL_PSWE,
    MCS51_SFR_BASE,
    MCS51_SFR_EIE1,
    MCS51_SFR_EIP1,
    MCS51_SFR_IE,
    MCS51_SFR_IP,
    MCS51_SFR_T2CON,
    MCS51_SFR_TCON,
    MCS51_XDATA_BASE,
    C8051F33xInterrupt,
    MCS51Interrupt,
    MCS51InterruptState,
    mcs51_flash_owns_store,
    mcs51_flash_programming,
    mcs51_flash_store,
    mcs51_interrupt_sfrs,
    mcs51_interrupt_to_take,
    mcs51_interrupts,
    mcs51_pop_sfr_page,
    mcs51_push_sfr_page,
    mcs51_raise_interrupt,
    mcs51_read_idata,
    mcs51_return_address,
    mcs51_service_interrupts,
    mcs51_sfr_paging,
    mcs51_write_idata,
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
                self.paging = None
                self.flash = None

            def write_register(self, name: str, value: int) -> None:
                self.registers[name] = value

            def set_interrupt_sources(self, emulator, sources) -> None:
                self.sources = sources

            def set_sfr_paging(self, emulator, paging) -> None:
                self.paging = paging

            def set_flash_programming(self, emulator, flash) -> None:
                self.flash = flash

        for device, xpage_sfr, sources, paging, flash in (
            ("C8051F330", 0xAA, C8051F33xInterrupt, None, MCS51_C8051F33X_FLASH),
            ("C8051F040", 0xA2, MCS51Interrupt, MCS51_C8051F04X_SFR_PAGING, None),
        ):
            with self.subTest(device=device):
                emulator = Emulator()
                MCS51Device(device).apply(emulator)
                self.assertEqual(emulator.registers, {"xpage_sfr": xpage_sfr})
                self.assertIs(emulator.sources, sources)
                self.assertIs(emulator.paging, paging)
                self.assertIs(emulator.flash, flash)

    def test_emulators_that_cannot_take_its_interrupts_are_refused(self):
        class Emulator:
            def write_register(self, name: str, value: int) -> None:
                pass

        with self.assertRaises(exceptions.ConfigurationError):
            MCS51Device("C8051F330").apply(Emulator())


class MCS51SFRPagingTests(unittest.TestCase):
    paging = MCS51_C8051F04X_SFR_PAGING

    def test_lookup(self):
        self.assertIs(mcs51_sfr_paging("c8051f041-gq"), self.paging)
        self.assertIs(mcs51_sfr_paging("C8051F064"), self.paging)
        self.assertIs(mcs51_sfr_paging("C8051F131"), MCS51_C8051F12X_SFR_PAGING)
        self.assertIs(mcs51_sfr_paging("C8051F368"), MCS51_C8051F36X_SFR_PAGING)
        for device in ("C8051F330", "C8051F020"):
            with self.subTest(device=device):
                self.assertIsNone(mcs51_sfr_paging(device))
        for device in ("C8051F920",):
            with self.subTest(device=device):
                with self.assertRaises(ValueError):
                    mcs51_sfr_paging(device)

    def test_devices_paged_without_a_table_are_not_paged(self):
        with self.assertLogs("smallworld.state.cpus.mcs51", "WARNING"):
            self.assertIsNone(MCS51Device("C8051F920").sfr_paging)

    def test_c8051f36x_pages_through_0xa7(self):
        paging = MCS51_C8051F36X_SFR_PAGING
        self.assertEqual((paging.sfrpage, paging.stack_enable), (0xA7, (0xFE5, 1)))
        lo, hi = paging.paged_masks()
        # SFRPAGE and TCON are shared; PSCTL and FLKEY, on page 0, are not.
        self.assertEqual((lo >> 0x27 & 1, lo >> 0x08 & 1), (0, 0))
        self.assertEqual((lo >> 0x0F & 1, lo >> 0x37 & 1), (1, 1))

    def test_c8051f12x_shares_psbank(self):
        paging = MCS51_C8051F12X_SFR_PAGING
        self.assertEqual(paging.shared - self.paging.shared, {0xB1})
        self.assertEqual(paging.paged_masks()[0] >> 0x31 & 1, 0)
        self.assertEqual(self.paging.paged_masks()[0] >> 0x31 & 1, 1)

    def test_masks_mark_every_sfr_but_the_shared(self):
        lo, hi = self.paging.paged_masks()
        for sfr in range(0x80, 0x100):
            mask, bit = (lo, sfr - 0x80) if sfr < 0xC0 else (hi, sfr - 0xC0)
            with self.subTest(sfr=hex(sfr)):
                self.assertEqual(bool(mask >> bit & 1), sfr not in self.paging.shared)
        # SFRPAGE, IE and ACC are shared; TCON and TMR2CN are not.
        self.assertEqual(lo >> 4 & 1, 0)
        self.assertEqual(lo >> 0x28 & 1, 0)
        self.assertEqual(hi >> 0x20 & 1, 0)
        self.assertEqual(lo >> 8 & 1, 1)
        self.assertEqual(hi >> 8 & 1, 1)

    def stack(self, enabled: bool) -> typing.Dict[int, int]:
        sfr, mask = self.paging.stack_enable
        return {sfr: mask if enabled else 0, 0x84: 1, 0x85: 2, 0x86: 3}

    def test_push_and_pop(self):
        values = self.stack(True)

        def write_sfr(address: int, value: int) -> None:
            values[address] = value

        self.assertTrue(mcs51_push_sfr_page(self.paging, values.get, write_sfr, 0xF))
        self.assertEqual((values[0x84], values[0x85], values[0x86]), (0xF, 1, 2))
        self.assertTrue(mcs51_pop_sfr_page(self.paging, values.get, write_sfr))
        self.assertEqual((values[0x84], values[0x85], values[0x86]), (1, 2, 2))

    def test_disabled_stack_is_left_alone(self):
        values = self.stack(False)

        def write_sfr(address: int, value: int) -> None:
            values[address] = value

        self.assertFalse(mcs51_push_sfr_page(self.paging, values.get, write_sfr, 0))
        self.assertFalse(mcs51_pop_sfr_page(self.paging, values.get, write_sfr))
        self.assertEqual((values[0x84], values[0x85], values[0x86]), (1, 2, 3))


class MCS51FlashTests(unittest.TestCase):
    flash = MCS51_C8051F33X_FLASH
    psctl = MCS51_SFR_BASE + MCS51_C8051F33X_FLASH.psctl
    flkey = MCS51_SFR_BASE + MCS51_C8051F33X_FLASH.flkey

    def setUp(self):
        self.memory: typing.Dict[int, int] = {}

    def read_memory(self, address: int, size: int) -> bytes:
        return bytes(self.memory.get(address + i, 0) for i in range(size))

    def write_memory(self, address: int, content: bytes) -> None:
        for i, byte in enumerate(content):
            self.memory[address + i] = byte

    def store(self, address: int, value: int) -> bool:
        if not mcs51_flash_owns_store(self.flash, address, self.read_memory):
            return False
        mcs51_flash_store(
            self.flash, address, value, self.read_memory, self.write_memory
        )
        return True

    def keys(self, *values: int) -> int:
        for value in values:
            self.assertTrue(self.store(self.flkey, value))
        return self.memory[self.flkey]

    def test_lookup(self):
        self.assertIs(mcs51_flash_programming("c8051f335-gm"), self.flash)
        self.assertIsNone(mcs51_flash_programming("C8051F310"))
        with self.assertLogs("smallworld.state.cpus.mcs51", "WARNING"):
            self.assertIsNone(MCS51Device("C8051F020").flash)

    def test_keys(self):
        self.assertEqual(self.keys(0xA5), MCS51_FLKEY_FIRST_KEY)
        self.assertEqual(self.keys(0xF1), MCS51_FLKEY_UNLOCKED)

    def test_wrong_keys_disable_until_reset(self):
        for keys in ((0xF1,), (0xA5, 0xA5), (0xA5, 0xF1, 0xA5)):
            with self.subTest(keys=keys):
                self.setUp()
                self.assertEqual(self.keys(*keys), MCS51_FLKEY_DISABLED)
                self.assertEqual(self.keys(0xA5, 0xF1), MCS51_FLKEY_DISABLED)

    def test_movx_writes_are_flashs_only_with_pswe(self):
        address = MCS51_XDATA_BASE + 0x1A00
        self.assertFalse(self.store(address, 0))
        self.assertFalse(self.store(MCS51_SFR_BASE + 0x90, 0))
        self.memory[self.psctl] = MCS51_PSCTL_PSWE
        self.assertTrue(self.store(address, 0))

    def test_write_clears_bits_and_relocks(self):
        self.memory[self.psctl] = MCS51_PSCTL_PSWE
        self.memory[MCS51_CODE_BASE + 0x1A01] = 0x5A
        self.keys(0xA5, 0xF1)
        self.store(MCS51_XDATA_BASE + 0x1A01, 0x0F)
        self.assertEqual(self.memory[MCS51_CODE_BASE + 0x1A01], 0x0A)
        self.assertEqual(self.memory[self.flkey], MCS51_FLKEY_LOCKED)

    def test_erase_sets_the_page(self):
        self.memory[self.psctl] = MCS51_PSCTL_PSWE | MCS51_PSCTL_PSEE
        self.keys(0xA5, 0xF1)
        self.store(MCS51_XDATA_BASE + 0x1B23, 0x00)
        flash = {a - MCS51_CODE_BASE for a, v in self.memory.items() if v == 0xFF}
        self.assertEqual(flash, set(range(0x1A00, 0x1C00)))
        self.assertEqual(self.memory[self.flkey], MCS51_FLKEY_LOCKED)

    def test_writing_while_locked_disables(self):
        self.memory[self.psctl] = MCS51_PSCTL_PSWE
        self.store(MCS51_XDATA_BASE + 0x1A00, 0x00)
        self.assertNotIn(MCS51_CODE_BASE + 0x1A00, self.memory)
        self.assertEqual(self.memory[self.flkey], MCS51_FLKEY_DISABLED)


class MCS51StackWrapTests(unittest.TestCase):
    """The 8051's stack wraps past internal RAM 0xFF to 0x00."""

    class Emulator:
        def __init__(self, sp: int):
            self.memory: typing.Dict[int, int] = {}
            self.sp = sp

        def read_register(self, name: str) -> int:
            assert name == "sp"
            return self.sp

        def write_register(self, name: str, value: int) -> None:
            assert name == "sp"
            self.sp = value

        def read_memory(self, address: int, size: int) -> bytes:
            for a in range(address, address + size):
                assert MCS51_IDATA_BASE <= a < MCS51_IDATA_BASE + 0x100, hex(a)
            return bytes(self.memory.get(a, 0) for a in range(address, address + size))

        def write_memory(self, address: int, content: bytes) -> None:
            for i, byte in enumerate(content):
                assert MCS51_IDATA_BASE <= address + i < MCS51_IDATA_BASE + 0x100
                self.memory[address + i] = byte

    def test_return_address_across_the_wrap(self):
        # LCALL pushed 0x1234 low byte first at 0xFF, then high at 0x00.
        emulator = self.Emulator(sp=0x00)
        emulator.memory[MCS51_IDATA_BASE + 0xFF] = 0x34
        emulator.memory[MCS51_IDATA_BASE + 0x00] = 0x12
        self.assertEqual(mcs51_return_address(emulator, pop=True), 0x1234)
        self.assertEqual(emulator.sp, 0xFE)

    def test_reads_and_writes_wrap(self):
        emulator = self.Emulator(sp=0)
        mcs51_write_idata(emulator, -1, b"\x01\x02\x03")
        self.assertEqual(emulator.memory[MCS51_IDATA_BASE + 0xFF], 0x01)
        self.assertEqual(emulator.memory[MCS51_IDATA_BASE + 0x01], 0x03)
        self.assertEqual(mcs51_read_idata(emulator, 0xFF, 3), b"\x01\x02\x03")


if __name__ == "__main__":
    unittest.main()
