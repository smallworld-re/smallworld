/* SFR pages on the EFM8BB2.
 *
 * Built only for the EFM8BB2 (efm8bb2.h comes in through mcs51_cc.sh's
 * --device), which has SFRs on pages 0x00, 0x10 and 0x20, many of them on
 * page 0 and one other: 0xC3 is ADC0GTL on pages 0x00 and 0x10, and
 * SMB0FCN0 on page 0x20, for one.  Main stores what it reads back in
 * result[], and the timer handlers the pages they find in isr[].
 *
 * Its page stack is five levels deep, SFRPAGE and four that firmware reads
 * through SFRSTACK, which shows the level SFRPGCN's SFRPGIDX selects.  Timer
 * 1's handler, at high priority, preempts Timer 0's, and reads the levels.
 */

#define SFRPGEN 0x01

__xdata unsigned char result[8];
__xdata unsigned char isr[8];
__xdata unsigned char isr_count;
__xdata unsigned char nest;

static void log_isr(unsigned char value)
{
    /* Past what main expects, log nothing, rather than overwrite what
     * follows isr[]. */
    if (isr_count < sizeof isr)
        isr[isr_count++] = value;
}

void timer0_isr(void) __interrupt(1)
{
    log_isr(SFRPAGE);
    if (nest) {
        /* Raise Timer 1's interrupt from page 0x10; its handler runs at
         * once, and RETI returns here, to page 0x10. */
        SFRPAGE = 0x10;
        TF1 = 1;
        log_isr(SFRPAGE);
    }
}

void timer1_isr(void) __interrupt(3)
{
    unsigned char level;

    log_isr(SFRPAGE);
    /* SFRSTACK's levels: SFRPAGE, now 0x10, Timer 0's handler's page and
     * main's. */
    SFRPAGE = 0x10;
    for (level = 0; level < 3; level++) {
        SFRPGCN = (level << 4) | SFRPGEN;
        log_isr(SFRSTACK);
    }
    SFRPGCN = SFRPGEN;
}

void main(void)
{
    unsigned char i;

    /* One address, page 0's SFR on page 0x10 too, but another on 0x20. */
    SFRPAGE = 0x00;
    ADC0GTL = 0x11;
    SFRPAGE = 0x20;
    SMB0FCN0 = 0x22;
    SFRPAGE = 0x10;
    result[0] = ADC0GTL;
    SFRPAGE = 0x20;
    result[1] = SMB0FCN0;

    /* And page 0's on page 0x20 too, but another on 0x10. */
    CRC0CN0 = 0x33;
    SFRPAGE = 0x10;
    EIE2 = 0x04;
    SFRPAGE = 0x00;
    result[2] = CRC0CN0;
    SFRPAGE = 0x10;
    result[3] = EIE2;

    /* Bits too: 0xC8 is TMR2CN0 on pages 0x00 and 0x10, and SCON1 on 0x20. */
    TR2 = 1;
    SFRPAGE = 0x20;
    RI1 = 1;
    SFRPAGE = 0x00;
    result[4] = TMR2CN0;
    SFRPAGE = 0x20;
    result[5] = SCON1;

    /* An SFR on every page is the same on each. */
    TMOD = 0x5A;
    SFRPAGE = 0x10;
    result[6] = TMOD;

    /* SFRPGCN, on page 0x10, leaves CRC0FLIP, at its address on page 0,
     * alone; enable the page stack with it. */
    SFRPAGE = 0x00;
    CRC0FLIP = 0x77;
    SFRPAGE = 0x10;
    SFRPGCN = SFRPGEN;
    SFRPAGE = 0x00;
    result[7] = CRC0FLIP;

    /* Taking Timer 0's interrupt selects its page, that of its flags - TCON,
     * on every page, is page 0's - and pushes main's, 0x20; its handler
     * raises Timer 1's, which pushes it.  RETI pops each. */
    PT1 = 1;
    ET0 = 1;
    ET1 = 1;
    nest = 1;
    TF0 = 1;
    SFRPAGE = 0x20;
    EA = 1;
    for (i = 0; i < 100 && isr_count != 6; i++)
        ;
    log_isr(SFRPAGE);

    /* With the page stack disabled, an interrupt leaves the page alone. */
    EA = 0;
    nest = 0;
    SFRPAGE = 0x10;
    SFRPGCN = 0x00;
    TF0 = 1;
    SFRPAGE = 0x20;
    EA = 1;
    for (i = 0; i < 100 && isr_count != 8; i++)
        ;
}
