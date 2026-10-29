/* SDCC's C library, run as compiled or replaced with SmallWorld's models.
 *
 * The mcs51_sdcc scenario runs this twice: once as SDCC built it, library
 * and all, and once with every library function it calls replaced by
 * SmallWorld's C99 models.  The results must be the same.  Output from
 * puts and printf goes through putchar, below, into out[] when the
 * library runs, and to the scenario's stdout when the models do.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__xdata char out[32];
__xdata unsigned char outlen;

int putchar(int c)
{
    out[outlen++] = c;
    return c;
}

__xdata char buf[32];
__xdata char buf2[16];
__xdata char fmt[32];

__xdata int r_strlen;
__xdata int r_strcmp;
__xdata int r_strchr;
__xdata int r_upper;
__xdata int r_atoi;
__xdata int r_abs;
__xdata int r_sprintf;
__xdata int r_malloc;

void main(void)
{
    char *p;

    strcpy(buf, "hello");
    strcat(buf, ", 8051");
    r_strlen = strlen(buf);
    r_strcmp = strcmp(buf, "hello");
    r_strchr = strchr(buf, ',') - buf;
    memset(buf2, 'z', 3);
    memcpy(buf2 + 3, buf, 5);
    buf2[8] = 0;
    r_upper = toupper('q');
    r_atoi = atoi("-321");
    r_abs = abs(-42);
    r_sprintf = sprintf(fmt, "%d-%s-%x", -7, "ab", 0xbeef);
    p = malloc(16);
    if (p) {
        strcpy(p, "heap");
        r_malloc = strlen(p);
        free(p);
    } else {
        r_malloc = -1;
    }
    puts("done");
    printf("%d\n", 51);
}
