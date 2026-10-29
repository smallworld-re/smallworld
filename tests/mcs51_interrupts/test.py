"""Unit tests for the 8051's interrupt logic in smallworld.platforms.defs.mcs51.

The mcs51_diff scenario's interrupts program checks the backends against
ucsim_51; these cover the rules it cannot, where ucsim departs from the 8051
manual, and the logic's bookkeeping directly.
"""

import typing
import unittest

from smallworld.platforms.defs.mcs51 import (
    MCS51_IE_EA,
    MCS51_OPCODE_RETI,
    MCS51_SFR_BASE,
    MCS51_SFR_IE,
    MCS51_SFR_IP,
    MCS51_SFR_TCON,
    MCS51Interrupt,
    MCS51InterruptState,
    mcs51_interrupt_to_take,
    mcs51_raise_interrupt,
    mcs51_service_interrupts,
)

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
        self.assertEqual(state.previous, (ljmp, ALL, 0))

    def test_reti_ends_service_and_holds_one_instruction(self):
        read_sfr = sfrs(ie=ALL, tcon=TF0)
        state = MCS51InterruptState((0,), (MCS51_OPCODE_RETI, ALL, 0))
        state, source = self.service(state, read_sfr)
        self.assertIsNone(source)
        self.assertEqual(state.in_service, ())
        state, source = self.service(state, read_sfr)
        self.assertIs(source, MCS51Interrupt.TIMER0)

    def test_writing_ie_or_ip_holds_one_instruction(self):
        for previous in ((NOP, 0, 0), (NOP, ALL, 0x02)):
            state = MCS51InterruptState((), previous)
            state, source = self.service(state, sfrs(ie=ALL, tcon=TF0))
            self.assertIsNone(source, previous)
            _, source = self.service(state, sfrs(ie=ALL, tcon=TF0))
            self.assertIs(source, MCS51Interrupt.TIMER0, previous)

    def test_plain_ret_stays_in_service(self):
        ret = 0x22
        state = MCS51InterruptState((0,), (ret, ALL, 0))
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


if __name__ == "__main__":
    unittest.main()
