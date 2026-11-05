/* SFR pages on the C8051F360.
 *
 * Built only for the C8051F360 (its SDCC header comes in through
 * mcs51_cc.sh's --device), which, unlike the C8051F040, has SFRPAGE at 0xA7,
 * its SFRs on page 0 or 0x0F, and SFR0CN to enable the page stack: 0xA4 is
 * MAC0AL on page 0 and P0MDOUT on page 0x0F, for one.  Main stores what it
 * reads back in result[], and Timer 0's handler what page it finds itself
 * on in isr[].
 */

__xdata unsigned char result[4];
__xdata unsigned char isr[2];
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
    MAC0AL = 0x12;
    SFRPAGE = 0x0F;
    P0MDOUT = 0x34;
    SFRPAGE = 0;
    result[0] = MAC0AL;
    SFRPAGE = 0x0F;
    result[1] = P0MDOUT;

    /* An SFR on every page is the same on each. */
    P1 = 0x5A;
    SFRPAGE = 0;
    result[2] = P1;

    /* Taking an interrupt selects its page, that of its flags - Timer 0's
     * are in TCON, on every page, so page 0 - and pushes main's onto
     * SFRNEXT; RETI pops it back. */
    SFRPAGE = 0x0F;
    SFR0CN = 0x01;
    TF0 = 1;
    ET0 = 1;
    EA = 1;
    for (i = 0; i < 100 && isr_count != 2; i++)
        ;
    result[3] = SFRPAGE;
}
