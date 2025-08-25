#include <stdio.h>
#include <string.h>
#include <math.h>

#define LONG_OCT_4 "10220441102"
#define LONG_OCT_8 "411022044110220441102"
#define LONG_DEC_4 "1111638594"
#define LONG_DEC_8 "4774451407313060418"
#define LONG_HEX_4 "42424242"
#define LONG_HEX_8 "4242424242424242"
#define LONG_CON_4 0x42424242l
#define LONG_CON_8 0x4242424242424242l

// Different platforms produce different values
// for NaN, and for longs
#if defined(__aarch64__)
#define LONG_OCT_RES LONG_OCT_8
#define LONG_DEC_RES LONG_DEC_8
#define LONG_HEX_RES LONG_HEX_8
#define LONG_CON LONG_CON_8

#elif defined(__x86_64__)
#define LONG_OCT_RES LONG_OCT_8
#define LONG_DEC_RES LONG_DEC_8
#define LONG_HEX_RES LONG_HEX_8
#define LONG_CON LONG_CON_8

#elif defined(__arm__)
#define LONG_OCT_RES LONG_OCT_4
#define LONG_DEC_RES LONG_DEC_4
#define LONG_HEX_RES LONG_HEX_4
#define LONG_CON LONG_CON_4

#elif defined(__i386__)
#define LONG_OCT_RES LONG_OCT_4
#define LONG_DEC_RES LONG_DEC_4
#define LONG_HEX_RES LONG_HEX_4
#define LONG_CON LONG_CON_4

#elif defined(__mips64)
#define LONG_OCT_RES LONG_OCT_8
#define LONG_DEC_RES LONG_DEC_8
#define LONG_HEX_RES LONG_HEX_8
#define LONG_CON LONG_CON_8

#elif defined(__mips__)
#define LONG_OCT_RES LONG_OCT_4
#define LONG_DEC_RES LONG_DEC_4
#define LONG_HEX_RES LONG_HEX_4
#define LONG_CON LONG_CON_4

#elif defined(__powerpc__)
#define LONG_OCT_RES LONG_OCT_4
#define LONG_DEC_RES LONG_DEC_4
#define LONG_HEX_RES LONG_HEX_4
#define LONG_CON LONG_CON_4

#elif defined(__riscv)
#define LONG_OCT_RES LONG_OCT_8
#define LONG_DEC_RES LONG_DEC_8
#define LONG_HEX_RES LONG_HEX_8
#define LONG_CON LONG_CON_8

#else
#error "Unknown architecture"
#endif


#define TEST(fmt, exp, ...) \
    do { \
        fprintf((FILE *)0x47492a01, fmt, __VA_ARGS__); \
        puts(""); \
    } while(0)

int main(int argc, char *argv[]) {
    char buf[128];
    char *good = (char *)(size_t)0xdead;
    int bad = 0;

    puts("***Starting***");

    // %d: Signed decimal integer
    TEST("%d", "42", 42);
    TEST("%d", "-42", -42);
    TEST("%8d", "      42", 42);
    TEST("%-8d", "42      ", 42);
    TEST("%08d", "00000042", 42);
    TEST("%+d", "+42", 42);
    TEST("% d", " 42", 42);
    TEST("%*d", "      42", 8, 42);
    TEST("%hhd", "66", 0x42);
    TEST("%hd", "16962", 0x4242);
    TEST("%ld", LONG_DEC_RES, LONG_CON);
    TEST("%lld", "4774451407313060418", 0x4242424242424242ll);
    TEST("%zd", LONG_DEC_RES, (size_t)LONG_CON);
    // %i: Signed decimal integer
    TEST("%i", "42", 42);
    TEST("%i", "-42", -42);
    TEST("%8i", "      42", 42);
    TEST("%-8i", "42      ", 42);
    TEST("%08i", "00000042", 42);
    TEST("%+i", "+42", 42);
    TEST("% i", " 42", 42);
    TEST("%*i", "      42", 8, 42);
    TEST("%hhi", "66", 0x42);
    TEST("%hi", "16962", 0x4242);
    TEST("%li", LONG_DEC_RES, LONG_CON);
    TEST("%lli", "4774451407313060418", 0x4242424242424242ll);
    TEST("%zi", LONG_DEC_RES, (size_t)LONG_CON);
    // %o: Unsigned octal integer
    TEST("%o", "52", 42);
    TEST("%o", "37777777726", -42);
    TEST("%8o", "      52", 42);
    TEST("%-8o", "52      ", 42);
    TEST("%08o", "00000052", 42);
    TEST("%#8o", "     052", 42);
    TEST("%#08o", "00000052", 42);
    TEST("%*o", "      52", 8, 42);
    TEST("%hho", "102", 0x42);
    TEST("%ho", "41102", 0x4242);
    TEST("%lo", LONG_OCT_RES, LONG_CON);
    TEST("%llo", "411022044110220441102", 0x4242424242424242ll);
    TEST("%zo", LONG_OCT_RES, (size_t)LONG_CON);
    // %u: Unsigned decimal integer
    TEST("%u", "42", 42);
    TEST("%u", "4294967254", -42);
    TEST("%8u", "      42", 42);
    TEST("%-8u", "42      ", 42);
    TEST("%08u", "00000042", 42);
    TEST("%*u", "      42", 8, 42);
    TEST("%hhu", "66", 0x42);
    TEST("%hu", "16962", 0x4242);
    TEST("%lu", LONG_DEC_RES, LONG_CON);
    TEST("%llu", "4774451407313060418", 0x4242424242424242ll);
    TEST("%zu", LONG_DEC_RES, (size_t)LONG_CON);
    // %x: Unsigned hexadecimal integer, lower-case
    TEST("%x", "2a", 42);
    TEST("%x", "ffffffd6", -42);
    TEST("%8x", "      2a", 42);
    TEST("%-8x", "2a      ", 42);
    TEST("%08x", "0000002a", 42);
    TEST("%#8x", "    0x2a", 42);
    TEST("%*x", "      2a", 8, 42);
    TEST("%hhx", "42", 0x42);
    TEST("%hx", "4242", 0x4242);
    TEST("%lx", LONG_HEX_RES, LONG_CON);
    TEST("%llx", "4242424242424242", 0x4242424242424242ll);
    TEST("%zx", LONG_HEX_RES, (size_t)LONG_CON);
    // %X: Unsigned hexadecimal integer, upper-case
    TEST("%X", "2A", 42);
    TEST("%8X", "      2A", 42);
    TEST("%-8X", "2A      ", 42);
    TEST("%08X", "0000002A", 42);
    TEST("%#8X", "    0X2A", 42);
    TEST("%*X", "      2A", 8, 42);
    TEST("%hhX", "42", 0x42);
    TEST("%hX", "4242", 0x4242);
    TEST("%lX", LONG_HEX_RES, LONG_CON);
    TEST("%llX", "4242424242424242", 0x4242424242424242ll);
    TEST("%zX", LONG_HEX_RES, (size_t)LONG_CON);
    // %e: Scientific notation, lower-case
    TEST("%e", "4.200000e+01", 42.0);
    TEST("%e", "inf", INFINITY);
    TEST("%e", "nan", NAN);
    TEST("%16e", "    4.200000e+01", 42.0);
    TEST("%-16e", "4.200000e+01    ", 42.0);
    TEST("%016e", "00004.200000e+01", 42.0);
    TEST("%*e", "    4.200000e+01", 16, 42.0);
    TEST("%.e", "4e+00", 4.0);
    TEST("%.1e", "4.0e+00", 4.0);
    TEST("%.*e", "4.0000e+00", 4, 4.0);
    TEST("%#.e", "4.e+00", 4.0);
    // %E: Scientific notation, upper-case
    TEST("%E", "4.200000E+01", 42.0);
    TEST("%E", "INF", INFINITY);
    TEST("%E", "NAN", NAN);
    TEST("%16E", "    4.200000E+01", 42.0);
    TEST("%-16E", "4.200000E+01    ", 42.0);
    TEST("%016E", "00004.200000E+01", 42.0);
    TEST("%*E", "    4.200000E+01", 16, 42.0);
    TEST("%.E", "4E+00", 4.0);
    TEST("%.1E", "4.0E+00", 4.0);
    TEST("%.*E", "4.0000E+00", 4, 4.0);
    TEST("%#.E", "4.E+00", 4.0);
    // %f: Fixed-point notation, lower-case
    TEST("%f", "42.000000", 42.0);
    TEST("%f", "inf", INFINITY);
    TEST("%f", "nan", NAN);
    TEST("%16f", "       42.000000", 42.0);
    TEST("%-16f", "42.000000       ", 42.0);
    TEST("%016f", "000000042.000000", 42.0);
    TEST("%*f", "       42.000000", 16, 42.0);
    TEST("%.f", "4", 4.0);
    TEST("%.1f", "4.0", 4.0);
    TEST("%.*f", "4.0000", 4, 4.0);
    TEST("%#.f", "4.", 4.0);
    // %F: Fixed-point notation, upper-case
    TEST("%F", "42.000000", 42.0);
    TEST("%F", "INF", INFINITY);
    TEST("%F", "NAN", NAN);
    TEST("%16F", "       42.000000", 42.0);
    TEST("%-16F", "42.000000       ", 42.0);
    TEST("%016F", "000000042.000000", 42.0);
    TEST("%*F", "       42.000000", 16, 42.0);
    TEST("%.F", "4", 4.0);
    TEST("%.1F", "4.0", 4.0);
    TEST("%.*F", "4.0000", 4, 4.0);
    TEST("%#.F", "4.", 4.0);
    // %g: General notation, lower-case
    TEST("%g", "42", 42.0);
    TEST("%g", "4.2e+06", 4200000.0);
    TEST("%g", "inf", INFINITY);
    TEST("%g", "nan", NAN);
    TEST("%16g", "              42", 42.0);
    TEST("%-16g", "42              ", 42.0);
    TEST("%016g", "0000000000000042", 42.0);
    TEST("%*g", "              42", 16, 42.0);
    TEST("%.g", "4", 4.0);
    TEST("%.g", "4", 4.2);
    TEST("%.2g", "4", 4.0);
    TEST("%.2g", "4.2", 4.2);
    TEST("%.*g", "4", 4, 4.0);
    TEST("%.*g", "4.2", 4, 4.2);
    TEST("%#.2g", "4.0", 4.0);
    TEST("%#.2g", "4.2", 4.2);
    // %g: General notation, upper-case
    TEST("%G", "42", 42.0);
    TEST("%G", "4.2E+06", 4200000.0);
    TEST("%G", "INF", INFINITY);
    TEST("%G", "NAN", NAN);
    TEST("%16G", "              42", 42.0);
    TEST("%-16G", "42              ", 42.0);
    TEST("%016G", "0000000000000042", 42.0);
    TEST("%*G", "              42", 16, 42.0);
    TEST("%.G", "4", 4.0);
    TEST("%.G", "4", 4.2);
    TEST("%.2G", "4", 4.0);
    TEST("%.2G", "4.2", 4.2);
    TEST("%.*G", "4", 4, 4.0);
    TEST("%.*G", "4.2", 4, 4.2);
    TEST("%#.2G", "4.0", 4.0);
    TEST("%#.2G", "4.2", 4.2);
    // %c: Character
    TEST("%c", "f", 'f');
    // %c: String
    TEST("%s", "foobar", "foobar");
    TEST("%8s", "  foobar", "foobar");
    TEST("%.3s", "foo", "foobar");
    // %p: Pointer
    TEST("%p", "0x2a", (void *)42l);

    if(bad) {
        puts("Errors.  Check above");
        return 1;
    }
    puts("SUCCESS!");
    return *good;
}
