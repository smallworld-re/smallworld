/* SFR pages on the C8051F040.
 *
 * Built only for the C8051F040 (its SDCC header comes in through
 * mcs51_cc.sh's --device), which reaches most SFRs through the page SFRPAGE
 * selects: 0xCA is RCAP2L on page 0, RCAP3L on page 1 and RCAP4L on page 2,
 * for one.  Main stores what it reads back in result[], and Timer 0's
 * handler what page it finds itself on in isr[].
 */

__xdata unsigned char result[8];
__xdata unsigned char isr[4];
__xdata unsigned char isr_count;

void timer0_isr(void) __interrupt(1)
{
    isr[isr_count++] = SFRPAGE;
    isr[isr_count++] = SFRNEXT;
}

void main(void)
{
    unsigned char i;

    /* One address, a different SFR on each page. */
    SFRPAGE = 0;
    RCAP2L = 0x20;
    SFRPAGE = 1;
    RCAP3L = 0x31;
    SFRPAGE = 2;
    RCAP4L = 0x42;
    SFRPAGE = 0;
    result[0] = RCAP2L;
    SFRPAGE = 1;
    result[1] = RCAP3L;
    SFRPAGE = 2;
    result[2] = RCAP4L;

    /* Bits too: 0xC8 is TMR2CN on page 0 and P4 on page 0x0F. */
    SFRPAGE = 0;
    TR2 = 1;
    SFRPAGE = 0x0F;
    P4_3 = 1;
    SFRPAGE = 0;
    result[3] = TMR2CN;
    SFRPAGE = 0x0F;
    result[4] = P4;

    /* An SFR on every page is the same on each. */
    SFRPAGE = 2;
    P1 = 0x5A;
    SFRPAGE = 0;
    result[5] = P1;

    /* Popping SFRPAGE selects the page popped. */
    SFRPAGE = 1;
    __asm
        push _SFRPAGE
        mov _SFRPAGE,#0x02
        pop _SFRPAGE
    __endasm;
    result[6] = RCAP3L;

    /* Taking an interrupt selects its page, that of its flags - Timer 0's
     * are in TCON, on page 0 - and pushes main's onto SFRNEXT; RETI pops it
     * back. */
    SFRPAGE = 0x0F;
    SFRPGCN = 0x01; /* SFRPGEN */
    SFRPAGE = 0;
    TF0 = 1;
    ET0 = 1;
    SFRPAGE = 1;
    EA = 1;
    result[7] = SFRPAGE;

    /* With the page stack disabled, an interrupt leaves the page alone. */
    EA = 0;
    SFRPAGE = 0x0F;
    SFRPGCN = 0x00;
    SFRPAGE = 0;
    TF0 = 1;
    SFRPAGE = 1;
    EA = 1;
    for (i = 0; i < 100 && isr_count != 4; i++)
        ;
}
