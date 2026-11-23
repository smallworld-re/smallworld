/* The EFM8BB2 erasing its flash's two sizes of page.
 *
 * Built only for the EFM8BB2 (efm8bb2.h comes in through mcs51_cc.sh's
 * --device).  Its code flash is in 512-byte pages, but the 1 KiB at
 * 0xF800-0xFBFF, for nonvolatile data, in 64-byte pages.  The program erases
 * the page holding 0x1A23 and the one holding 0xF85A, writes a byte in the
 * second, and stores what it reads back, with MOVC, around each, in
 * result[].  The flash is otherwise written as on the C8051F330; see
 * flash.cip51.c.
 */

#define PSWE 0x01
#define PSEE 0x02

__xdata unsigned char result[10];

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
    /* Erase: a write anywhere in a page sets it all to 0xFF. */
    PSCTL = PSWE | PSEE;
    unlock();
    *(__xdata unsigned char *)0x1A23 = 0;
    unlock();
    *(__xdata unsigned char *)0xF85A = 0;
    PSCTL = 0;

    /* Write a byte in the small page. */
    PSCTL = PSWE;
    unlock();
    *(__xdata unsigned char *)0xF845 = 0x3C;
    PSCTL = 0;

    /* The large page and its neighbors. */
    result[0] = flash(0x19FF);
    result[1] = flash(0x1A00);
    result[2] = flash(0x1BFF);
    result[3] = flash(0x1C00);
    /* The small page and its neighbors. */
    result[4] = flash(0xF83F);
    result[5] = flash(0xF840);
    result[6] = flash(0xF845);
    result[7] = flash(0xF87F);
    result[8] = flash(0xF880);
    result[9] = FLKEY;
}
