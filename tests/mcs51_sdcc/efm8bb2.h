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

/* SFR paging: SFRPAGE, on every page, and SFRPGCN and SFRSTACK, on page
 * 0x10.  SFRPGCN's bit 0 is SFRPGEN, and bits 4-6 SFRPGIDX. */
__sfr __at(0xA7) SFRPAGE;
__sfr __at(0xCF) SFRPGCN;
__sfr __at(0xD7) SFRSTACK;

/* SFRs that share addresses: on page 0 and 0x10, page 0 and 0x20, or one
 * page, as Table 3.3 lists them. */
__sfr __at(0x89) TMOD;     /* every page */
__sfr __at(0xC3) ADC0GTL;  /* 0x00, 0x10 */
__sfr __at(0xC3) SMB0FCN0; /* 0x20 */
__sfr __at(0xC8) TMR2CN0;  /* 0x00, 0x10 */
__sfr __at(0xC8) SCON1;    /* 0x20 */
__sfr __at(0xCE) CRC0CN0;  /* 0x00, 0x20 */
__sfr __at(0xCE) EIE2;     /* 0x10 */
__sfr __at(0xCF) CRC0FLIP; /* 0x00, 0x20 */
__sbit __at(0xCA) TR2;     /* TMR2CN0 bit 2 */
__sbit __at(0xC8) RI1;     /* SCON1 bit 0 */

/* The 8051's interrupt SFRs, on every page. */
__sfr __at(0x88) TCON;
__sfr __at(0xA8) IE;
__sfr __at(0xB8) IP;
__sbit __at(0x8D) TF0;
__sbit __at(0x8F) TF1;
__sbit __at(0xA9) ET0;
__sbit __at(0xAB) ET1;
__sbit __at(0xAF) EA;
__sbit __at(0xBB) PT1;

#endif
