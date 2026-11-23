/* Included ahead of each C99 test built for the 8051; see mcs51_cc.sh --c99.
 *
 * SDCC's library has no exit, fabs or strerror, and leaves getchar and
 * putchar to the program.  Stubs for them are in mcs51_sdcc.c.
 */

/* SDCC exports getchar and putchar only if stdio.h declares them first. */
#include <stdio.h>

/* SDCC's stdio.h declares gets only before C11, though its library has it. */
char *gets(char *s);

void exit(int status);
double fabs(double x);
char *strerror(int errnum);
/* string.h makes strcoll a macro for strcmp; the test undefines it. */
int strcoll(const char *s1, const char *s2);
