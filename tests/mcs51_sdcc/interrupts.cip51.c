/* The C8051F330's interrupts beyond the 8052's.
 *
 * Built only for the C8051F330 (its SDCC header comes in through
 * mcs51_cc.sh's --device).  Main requests interrupts by setting their
 * flags, which the hardware allows; each handler logs its interrupt number
 * in order[] and clears its flag, and main logs markers (0xF0 and up)
 * between steps, so the log shows what ran when.
 *
 * Between two interrupts, after RETI, one instruction of main runs.  So
 * that a handler never runs in the middle of main's logging, main waits
 * for every handler it expects before logging; a bounded wait, so an
 * interrupt that never comes shows in the log rather than hanging.
 */

__xdata unsigned char order[32];
__xdata unsigned char n;
__xdata unsigned char nest;

#define LOG(id) (order[n++] = (id))

static void wait_for(unsigned char count)
{
    unsigned char i;
    for (i = 0; i < 100 && n != count; i++)
        ;
}

void timer2_isr(void) __interrupt(5)
{
    LOG(5);
    TF2L = 0;
}

void spi0_isr(void) __interrupt(6)
{
    LOG(6);
    SPIF = 0;
}

void smbus0_isr(void) __interrupt(7)
{
    LOG(7);
    SI = 0;
    if (nest) {
        /* Timer 3 is high priority now: it runs at once, inside this
         * low-priority handler. */
        nest = 0;
        TMR3CN |= 0x80; /* TF3H */
        LOG(0x70);
    }
}

void adc0_conversion_isr(void) __interrupt(10)
{
    LOG(10);
    AD0INT = 0;
}

void pca0_isr(void) __interrupt(11)
{
    LOG(11);
    CCF1 = 0;
}

void comparator0_isr(void) __interrupt(12)
{
    LOG(12);
    CPT0CN &= ~0x20; /* CP0RIF */
}

void timer3_isr(void) __interrupt(14)
{
    LOG(14);
    TMR3CN &= ~0x80; /* TF3H */
}

void main(void)
{
    /* Requests through IE and EIE1, all low priority, are taken in polling
     * order: SPI0, SMBus0, ADC0, Timer 3. */
    TMR3CN |= 0x80; /* TF3H */
    AD0INT = 1;
    SI = 1;
    SPIF = 1;
    IE = 0x40;                 /* ESPI0 */
    EIE1 = 0x01 | 0x08 | 0x80; /* ESMB0, EADC0, ET3 */
    EA = 1;
    wait_for(4);
    LOG(0xF0);

    /* EIP1 makes Timer 3 high priority, so it beats SPI0. */
    EA = 0;
    SPIF = 1;
    TMR3CN |= 0x80;
    EIP1 = 0x80; /* PT3 */
    EA = 1;
    wait_for(7);
    LOG(0xF1);

    /* A high-priority interrupt nests in a low-priority one. */
    nest = 1;
    SI = 1;
    LOG(0xF2);

    /* Timer 2's low-byte flag requests only while TF2LEN is set. */
    TF2L = 1;
    ET2 = 1;
    LOG(0xF3);
    TF2LEN = 1;
    LOG(0xF4);

    /* A PCA module's flag requests only while its ECCFn is set. */
    CCF1 = 1;
    EIE1 |= 0x10; /* EPCA0 */
    LOG(0xF5);
    PCA0CPM1 |= 0x01; /* ECCF1 */
    LOG(0xF6);

    /* Comparator0's rising-edge flag requests only while CP0RIE is set. */
    CPT0CN |= 0x20; /* CP0RIF */
    EIE1 |= 0x20;   /* ECP0 */
    LOG(0xF7);
    CPT0MD |= 0x20; /* CP0RIE */
    LOG(0xF8);
}
