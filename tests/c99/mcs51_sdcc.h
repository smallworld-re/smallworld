/* Included ahead of each C99 test built for the 8051; see mcs51_cc.sh --c99.
 *
 * SDCC's library has no exit, fabs or strerror, and leaves getchar and
 * putchar to the program.  These stand in for them so the tests link; the
 * runner replaces each with its model, and stops at exit as a failure.  None
 * should ever run.
 */

/* SDCC exports getchar and putchar only if stdio.h declares them first. */
#include <stdio.h>

/* SDCC's stdio.h declares gets only before C11, though its library has it. */
char *gets(char *s);

void exit(int status) {
    (void)status;
    for (;;) {
    }
}

double fabs(double x) {
    (void)x;
    exit(2);
    return 0;
}

char *strerror(int errnum) {
    (void)errnum;
    exit(2);
    return 0;
}

/* string.h makes strcoll a macro for strcmp; the test undefines it. */
int strcoll(const char *s1, const char *s2) {
    (void)s1;
    (void)s2;
    exit(2);
    return 0;
}

int getchar(void) {
    exit(2);
    return 0;
}

int putchar(int c) {
    (void)c;
    exit(2);
    return 0;
}
