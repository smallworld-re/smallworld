/* The EFM8BB2's interrupts.
 *
 * Built only for the EFM8BB2 (efm8bb2.h comes in through mcs51_cc.sh's
 * --device).  Main requests interrupts by setting their flags, which the
 * hardware allows; each handler logs its interrupt number and the SFR page
 * it starts on in order[], and clears its flag, and main logs markers (0xF0
 * and up) between steps, so the log shows what ran when.  The SFR page
 * stack is enabled, so each handler starts on the page of its flags.
 *
 * Between two interrupts, after RETI, one instruction of main runs.  So
 * that a handler never runs in the middle of main's logging, main waits
 * for every handler it expects before logging; a bounded wait, so an
 * interrupt that never comes shows in the log rather than hanging.
 */

#define SFRPGEN 0x01

__xdata unsigned char order[48];
__xdata unsigned char n;
__xdata unsigned char nest;

#define LOG(id) (order[n++] = (id))

static void wait_for(unsigned char count)
{
    unsigned char i;
    for (i = 0; i < 100 && n != count; i++)
        ;
}

void timer0_isr(void) __interrupt(1)
{
    LOG(1);
    LOG(SFRPAGE);
}

void smbus0_isr(void) __interrupt(7)
{
    LOG(7);
    LOG(SFRPAGE);
    SI = 0;
    if (nest == 3) {
        /* Timer 4, at priority 3, preempts this handler, at 2. */
        nest = 0;
        SFRPAGE = 0x10;
        TMR4CN0 |= 0x80; /* TF4H */
        LOG(0x72);
    }
}

void pca0_isr(void) __interrupt(11)
{
    LOG(11);
    LOG(SFRPAGE);
    PCA0PWM &= ~0x20; /* COVF */
}

void timer3_isr(void) __interrupt(14)
{
    LOG(14);
    LOG(SFRPAGE);
    TMR3CN0 &= ~0x80; /* TF3H */
    if (nest == 2) {
        /* SMBus0, at priority 2, preempts this handler, at 1. */
        nest = 3;
        SI = 1;
        LOG(0x71);
    } else if (nest == 4) {
        /* Timer 0, at priority 2 through IPH alone, preempts it too. */
        nest = 0;
        TF0 = 1;
        LOG(0x74);
    }
}

void uart1_isr(void) __interrupt(17)
{
    LOG(17);
    LOG(SFRPAGE);
    RI1 = 0;
    if (nest == 1) {
        /* Timer 3, at priority 1, preempts this handler, at 0. */
        nest = 2;
        SFRPAGE = 0x00;
        TMR3CN0 |= 0x80; /* TF3H */
        LOG(0x70);
    }
}

void i2c0_isr(void) __interrupt(18)
{
    LOG(18);
    LOG(SFRPAGE);
    I2C0STAT &= ~0x20; /* I2C0INT */
}

void timer4_isr(void) __interrupt(19)
{
    LOG(19);
    LOG(SFRPAGE);
    TMR4CN0 &= ~0x80; /* TF4H */
}

void main(void)
{
    SFRPAGE = 0x10;
    SFRPGCN = SFRPGEN;

    /* Requests through EIE1 and EIE2, all at priority 0, are taken in
     * polling order: SMBus0, Timer 3, UART1, I2C0, Timer 4.  UART1's RI
     * requests only while RIE is set; it resets set, but SFRs start at 0
     * here. */
    SFRPAGE = 0x00;
    TMR3CN0 |= 0x80; /* TF3H */
    SI = 1;
    SFRPAGE = 0x20;
    UART1FCN1 = 0x01; /* RIE */
    RI1 = 1;
    I2C0STAT |= 0x20; /* I2C0INT */
    SFRPAGE = 0x10;
    TMR4CN0 |= 0x80;    /* TF4H */
    EIE1 = 0x01 | 0x80; /* ESMB0, ET3 */
    EIE2 = 0x04 | 0x08 | 0x10; /* ES1, EI2C0, ET4 */
    EA = 1;
    wait_for(10);
    LOG(0xF0);

    /* Four priority levels, each preempting the one below: UART1 at 0,
     * Timer 3 at 1 (EIP1), SMBus0 at 2 (EIP1H) and Timer 4 at 3 (EIP2 and
     * EIP2H), each raised by the handler below it. */
    EIP1 = 0x80;  /* PT3 */
    EIP1H = 0x01; /* PHSMB0 */
    EIP2 = 0x10;  /* PT4 */
    EIP2H = 0x10; /* PHT4 */
    nest = 1;
    SFRPAGE = 0x20;
    RI1 = 1;
    SFRPAGE = 0x10;
    wait_for(22);
    LOG(0xF1);

    /* Priority 2 through EIP2H alone beats priority 1 through EIP2 alone,
     * whatever the polling order: Timer 4 before UART1. */
    EA = 0;
    EIP1 = 0;
    EIP1H = 0;
    EIP2 = 0x04;  /* PS1 */
    EIP2H = 0x10; /* PHT4 */
    TMR4CN0 |= 0x80;
    SFRPAGE = 0x20;
    RI1 = 1;
    SFRPAGE = 0x10;
    EA = 1;
    wait_for(27);
    LOG(0xF2);

    /* IPH makes Timer 0 priority 2, so it preempts Timer 3, at 1. */
    EIP2 = 0;
    EIP2H = 0;
    EIP1 = 0x80;  /* PT3 */
    IPH = 0x02;   /* PHT0 */
    ET0 = 1;
    nest = 4;
    SFRPAGE = 0x00;
    TMR3CN0 |= 0x80;
    SFRPAGE = 0x10;
    wait_for(33);
    LOG(0xF3);

    /* UART1's RI requests only while RIE is set. */
    SFRPAGE = 0x20;
    UART1FCN1 = 0x00;
    RI1 = 1;
    LOG(0xF4);
    UART1FCN1 = 0x01; /* RIE */
    wait_for(37);
    LOG(0xF5);

    /* PCA0's COVF, in PCA0PWM, requests only while ECOV is set. */
    SFRPAGE = 0x10;
    EIE1 |= 0x10;     /* EPCA0 */
    PCA0PWM = 0x20;   /* COVF */
    LOG(0xF6);
    PCA0PWM = 0x60;   /* ECOV, COVF */
    wait_for(41);
    LOG(0xF7);
}
