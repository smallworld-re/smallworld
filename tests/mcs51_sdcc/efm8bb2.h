/* The Silicon Labs EFM8BB2's SFRs the mcs51_sdcc programs use.
 *
 * SDCC has no header for the EFM8 families, so mcs51_cc.sh's --device
 * includes this one instead.  The addresses are from the EFM8BB2 reference
 * manual, preliminary revision 0.3, Table 3.3.
 */

#ifndef EFM8BB2_H
#define EFM8BB2_H

/* EMI0CN, on every page, pages MOVX @Ri; SDCC's startup code pages pdata
 * through _XPAGE, which the linker map records as __XPAGE. */
__sfr __at(0xE7) EMI0CN;
__sfr __at(0xE7) _XPAGE;

/* Flash programming, on every page. */
__sfr __at(0x8F) PSCTL;
__sfr __at(0xB7) FLKEY;

#endif
