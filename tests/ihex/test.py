"""Unit tests for Executable.from_ihex, the ASxxxx linker map reader, and
the 8051 device lookup that stands in for a map's ``__XPAGE``."""

import io
import unittest

from smallworld import exceptions, platforms
from smallworld.platforms.defs.mcs51 import (
    MCS51_CODE_BASE,
    MCS51_IDATA_BASE,
    MCS51_XDATA_BASE,
    mcs51_xpage_sfr,
)
from smallworld.state.memory.code import Executable
from smallworld.state.memory.ihex import read_asxxxx_map

MCS51 = platforms.Platform(platforms.Architecture.MCS51, platforms.Byteorder.BIG)


def record(kind: int, address: int, data: bytes = b"") -> str:
    """One Intel HEX record, with its checksum."""
    body = bytes([len(data)]) + address.to_bytes(2, "big") + bytes([kind]) + data
    return ":" + (body + bytes([-sum(body) & 0xFF])).hex().upper() + "\n"


END = record(0x01, 0)

# The shape of an SDCC 4.6 map: each page starts with a form feed, areas
# repeat on page breaks, and absolute areas have names with spaces.
MAP = """\
\fASxxxx Linker V05.50.4-SDLD,  page 1.
Hexadecimal  [32-Bits]

Area                                    Addr        Size        Decimal Bytes (Attributes)
--------------------------------        ----        ----        ------- ----- ------------
CABS                                00000000    00000000 =           0. bytes (ABS,CON,CODE)

         Value  Global                             Global Defined In Module
         -----  --------------------------------   ------------------------
C:   000000DF  l_SSEG

\fASxxxx Linker V05.50.4-SDLD,  page 2.
Hexadecimal  [32-Bits]

Area                                    Addr        Size        Decimal Bytes (Attributes)
--------------------------------        ----        ----        ------- ----- ------------
.  .ABS.                            00000000    00000000 =           0. bytes (ABS,CON)

         Value  Global                             Global Defined In Module
         -----  --------------------------------   ------------------------
     00000090  _P1                                prog
     000000AA  __XPAGE                            prog

\fASxxxx Linker V05.50.4-SDLD,  page 3.
Hexadecimal  [32-Bits]

Area                                    Addr        Size        Decimal Bytes (Attributes)
--------------------------------        ----        ----        ------- ----- ------------
DSEG                                00000008    00000002 =           2. bytes (REL,CON)

         Value  Global                             Global Defined In Module
         -----  --------------------------------   ------------------------
     0000000A  _f_PARM_2                          prog

\fASxxxx Linker V05.50.4-SDLD,  page 4.
Hexadecimal  [32-Bits]

Area                                    Addr        Size        Decimal Bytes (Attributes)
--------------------------------        ----        ----        ------- ----- ------------
XSEG                                00000001    00000002 =           2. bytes (REL,CON,XDATA)

         Value  Global                             Global Defined In Module
         -----  --------------------------------   ------------------------
D:   00000001  _buf                               prog

\fASxxxx Linker V05.50.4-SDLD,  page 5.
Hexadecimal  [32-Bits]

Area                                    Addr        Size        Decimal Bytes (Attributes)
--------------------------------        ----        ----        ------- ----- ------------
CSEG                                000000AA    00000010 =          16. bytes (REL,CON,CODE)

         Value  Global                             Global Defined In Module
         -----  --------------------------------   ------------------------
C:   000000AA  _main                              prog
C:   000000B2  _f                                 prog

\fASxxxx Linker V05.50.4-SDLD,  page 6.

User Base Address Definitions

HOME = 0x0000
"""


class IHexLoaderTests(unittest.TestCase):
    def load(self, text: str, **kwargs) -> Executable:
        return Executable.from_ihex(io.StringIO(text), **kwargs)

    def test_contiguous_records_form_one_run(self):
        image = self.load(
            record(0x00, 0x10, b"\x01\x02") + record(0x00, 0x12, b"\x03") + END
        )
        self.assertEqual(
            [(k, v.to_bytes()) for k, v in image.items()], [(0x10, b"\x01\x02\x03")]
        )
        self.assertEqual(list(image.bounds), [(0x10, 0x13)])

    def test_gaps_are_separate_runs(self):
        image = self.load(
            record(0x00, 0x20, b"\xbb") + record(0x00, 0x00, b"\xaa") + END
        )
        self.assertEqual(
            [(k, v.to_bytes()) for k, v in image.items()],
            [(0x00, b"\xaa"), (0x20, b"\xbb")],
        )

    def test_out_of_order_records_are_joined(self):
        image = self.load(
            record(0x00, 0x02, b"\x02") + record(0x00, 0x00, b"\x00\x01") + END
        )
        self.assertEqual(
            [(k, v.to_bytes()) for k, v in image.items()], [(0, b"\x00\x01\x02")]
        )

    def test_binary_file_objects_are_read(self):
        image = Executable.from_ihex(
            io.BytesIO((record(0x00, 0, b"\x5a") + END).encode())
        )
        self.assertEqual(image[0].to_bytes(), b"\x5a")

    def test_address_moves_the_image(self):
        image = self.load(record(0x00, 0x04, b"\x01") + END, address=0x1000)
        self.assertEqual(image.address, 0x1000)
        self.assertEqual(list(image.bounds), [(0x1004, 0x1005)])

    def test_extended_linear_address_and_start_address(self):
        image = self.load(
            record(0x04, 0, b"\x00\x01")
            + record(0x00, 0x0002, b"\x99")
            + record(0x05, 0, b"\x00\x01\x00\x02")
            + END
        )
        self.assertEqual(list(image.keys()), [0x10002])
        self.assertEqual(image.entrypoint, 0x10002)

    def test_bad_checksum_is_refused(self):
        line = record(0x00, 0, b"\x01")
        bad = line[:-3] + ("00" if line[-3:-1] != "00" else "01") + "\n"
        with self.assertRaises(exceptions.ConfigurationError):
            self.load(bad + END)

    def test_overlapping_data_is_refused(self):
        with self.assertRaises(exceptions.ConfigurationError):
            self.load(record(0x00, 0, b"\x01\x02") + record(0x00, 1, b"\x03") + END)

    def test_data_after_end_of_file_is_refused(self):
        with self.assertRaises(exceptions.ConfigurationError):
            self.load(END + record(0x00, 0, b"\x01"))

    def test_symbols_need_a_map(self):
        image = self.load(END)
        with self.assertRaises(exceptions.ConfigurationError):
            image.get_symbol_value("_main")


class AsxxxxMapTests(unittest.TestCase):
    def load(self, **kwargs) -> Executable:
        return Executable.from_ihex(
            io.StringIO(END), map_file=io.StringIO(MAP), **kwargs
        )

    def test_reads_every_global_with_its_area(self):
        symbols = read_asxxxx_map(MAP)
        self.assertEqual(
            sorted(symbols),
            ["_P1", "__XPAGE", "_buf", "_f", "_f_PARM_2", "_main", "l_SSEG"],
        )
        self.assertEqual(symbols["_main"].area, "CSEG")
        self.assertEqual(symbols["_main"].module, "prog")
        self.assertEqual(symbols["_P1"].area, ".  .ABS.")
        self.assertIn("XDATA", symbols["_buf"].attributes)

    def test_mcs51_symbols_land_in_their_spaces(self):
        image = self.load(platform=MCS51)
        self.assertEqual(image.get_symbol_value("_main"), MCS51_CODE_BASE + 0xAA)
        self.assertEqual(image.get_symbol_value("_buf"), MCS51_XDATA_BASE + 1)
        self.assertEqual(image.get_symbol_value("_f_PARM_2"), MCS51_IDATA_BASE + 0xA)

    def test_absolute_symbols_keep_their_values(self):
        image = self.load(platform=MCS51)
        self.assertEqual(image.get_symbol_value("_P1"), 0x90)
        self.assertEqual(image.get_symbol_value("l_SSEG"), 0xDF)

    def test_other_platforms_move_symbols_with_the_image(self):
        image = self.load(address=0x100)
        self.assertEqual(image.get_symbol_value("_main"), 0x1AA)
        self.assertEqual(image.get_symbol_value("_buf"), 0x101)

    def test_symbol_names(self):
        self.assertIn("_f_PARM_2", self.load().get_symbol_names())

    def test_unknown_symbol_is_an_error(self):
        with self.assertRaises(exceptions.ConfigurationError):
            self.load().get_symbol_value("_nothing")

    def test_xpage_sfr_is_the_maps_xpage(self):
        self.assertEqual(self.load(platform=MCS51).xpage_sfr, 0xAA)

    def test_xpage_sfr_needs_xpage_in_the_map(self):
        self.assertIsNone(Executable.from_ihex(io.StringIO(END)).xpage_sfr)
        without = MAP.replace("__XPAGE", "_EMI0CN")
        image = Executable.from_ihex(io.StringIO(END), map_file=io.StringIO(without))
        self.assertIsNone(image.xpage_sfr)

    def test_other_text_is_refused(self):
        with self.assertRaises(exceptions.ConfigurationError):
            read_asxxxx_map("Memory Configuration\n\nName Origin Length\n")

    def test_non_hexadecimal_maps_are_refused(self):
        with self.assertRaises(exceptions.ConfigurationError):
            read_asxxxx_map(MAP.replace("Hexadecimal  [32-Bits]", "Octal  [32-Bits]"))


class MCS51XpageSfrTests(unittest.TestCase):
    def test_silicon_labs_families(self):
        for device, sfr in (
            ("C8051F005", 0xAF),
            ("C8051F019", 0xAF),
            ("C8051F206", 0xAF),
            ("C8051F040", 0xA2),
            ("C8051F064", 0xA2),
            ("C8051F131", 0xA2),
            ("C8051F330", 0xAA),
            ("C8051F368", 0xAA),
            ("C8051F411", 0xAA),
            ("C8051F931", 0xAA),
            ("C8051T634", 0xAA),
        ):
            with self.subTest(device=device):
                self.assertEqual(mcs51_xpage_sfr(device), sfr)

    def test_other_vendors(self):
        self.assertEqual(mcs51_xpage_sfr("CC2530"), 0x93)
        self.assertEqual(mcs51_xpage_sfr("AX8052F143"), 0xD9)
        self.assertEqual(mcs51_xpage_sfr("MSC1210"), 0x92)
        self.assertEqual(mcs51_xpage_sfr("XC866"), 0xB3)

    def test_case_and_suffixes_are_ignored(self):
        self.assertEqual(mcs51_xpage_sfr("c8051f330-gm"), 0xAA)

    def test_unknown_devices_are_refused(self):
        # The C8051F30x has no _XPAGE in SDCC's headers; the 80C51 pages
        # through P2, which is the default.
        for device in ("C8051F300", "80C51", "8051"):
            with self.subTest(device=device):
                with self.assertRaises(ValueError):
                    mcs51_xpage_sfr(device)


if __name__ == "__main__":
    unittest.main()
