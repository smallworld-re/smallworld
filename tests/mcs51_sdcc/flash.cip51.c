/* The C8051F330 writing its own flash.
 *
 * Built only for the C8051F330 (its SDCC header comes in through
 * mcs51_cc.sh's --device).  With PSCTL's PSWE set, MOVX writes go to flash
 * rather than XDATA, once FLKEY has been unlocked with 0xA5 then 0xF1; with
 * PSEE set too, they erase the page.  The program erases and writes the
 * flash page at 0x1A00, and stores what it reads back, with MOVC, and what
 * FLKEY reads, in result[].  While PSWE is set, it keeps what it reads in
 * internal RAM, in flkey[]: a MOVX write would go to flash.
 */

#define PAGE 0x1A00
#define PSWE 0x01
#define PSEE 0x02

__xdata unsigned char result[16];
__data unsigned char flkey[5];

static void unlock(void)
{
    FLKEY = 0xA5;
    FLKEY = 0xF1;
}

static unsigned char flash(unsigned int address)
{
    return *(const __code unsigned char *)address;
}

void main(void)
{
    __xdata unsigned char *page = (__xdata unsigned char *)PAGE;

    /* Erase the page: a write anywhere in it sets it all to 0xFF.  FLKEY
     * reads the lock's state: first key written, unlocked, locked again. */
    PSCTL = PSWE | PSEE;
    FLKEY = 0xA5;
    flkey[0] = FLKEY;
    FLKEY = 0xF1;
    flkey[1] = FLKEY;
    page[0x10] = 0;
    flkey[2] = FLKEY;
    PSCTL = 0;

    /* Write two bytes, unlocking for each. */
    PSCTL = PSWE;
    unlock();
    page[0] = 0x5A;
    unlock();
    page[1] = 0xC3;

    /* Writing can only clear bits: 0x5A then 0x0F leaves 0x0A. */
    unlock();
    page[0] = 0x0F;

    /* Writing while locked writes nothing, and disables writes until
     * reset, even after the keys. */
    page[2] = 0x00;
    flkey[3] = FLKEY;
    unlock();
    page[3] = 0x00;
    flkey[4] = FLKEY;
    PSCTL = 0;

    /* Without PSWE, MOVX writes go to XDATA. */
    page[4] = 0x77;

    result[0] = flkey[0];
    result[1] = flkey[1];
    result[2] = flkey[2];
    result[3] = flkey[3];
    result[4] = flkey[4];
    result[5] = flash(PAGE);
    result[6] = flash(PAGE + 1);
    result[7] = flash(PAGE + 2);
    result[8] = flash(PAGE + 3);
    result[9] = flash(PAGE + 4);
    result[10] = flash(PAGE + 0x10);
    result[11] = flash(PAGE + 0x1FF);
}
