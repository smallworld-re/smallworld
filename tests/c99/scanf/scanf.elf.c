#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#if __WORDSIZE == 64
#define INTRES -1
#else
#define INTRES 2147483647
#endif

#define xstr(s) #s
#define str(s) xstr(s)

#define TEST(fmt, src, arg, exp, err) \
    do {\
        for(int i = strlen(src) - 1; i >= 0; i--) {\
            ungetc(src[i], file);\
        }\
        res = scanf(fmt, &arg); \
        if (res != 1) {\
            puts("Format");\
            puts(fmt);\
            printf("Did not convert: %d\n", res);\
            bad = 1; \
        } else if ((arg != exp) && (arg == arg || exp == exp)) { \
            puts("Format:"); \
            puts(fmt); \
            puts("Source:");\
            puts(src);\
            puts("Expected:");\
            printf(err, exp);\
            puts("Actual:");\
            printf(err, arg);\
            bad = 1;\
        }\
    } while(0)

#define TEST_STR(fmt, src, arg, exp, pop) \
    do {\
        if(bad_str) {\
            break;\
        }\
        for(int i = strlen(src) - 1; i >= 0; i--) {\
            ungetc(src[i], file);\
        }\
        res = scanf(fmt, &arg); \
        if (res != 1) {\
            puts("Format");\
            puts(fmt);\
            printf("Did not convert: %d\n", res);\
            bad = 1;\
        } else if (strcmp(arg, exp)) { \
            puts("Format:"); \
            puts(fmt); \
            puts("Source:");\
            puts(src);\
            puts("Expected:");\
            printf("%s\n", exp);\
            puts("Actual:");\
            printf("%s\n", arg);\
            printf("%02x\n", arg[3]);\
            bad = 1;\
        } else {\
            for(int i = 0; i < pop; i++) {\
                getc(file);\
            }\
        }\
    } while(0)

#define TEST_LEN(fmt, src, arg, exp, err) \
    do {\
        for(int i = strlen(src) - 1; i >= 0; i--) {\
            ungetc(src[i], file);\
        }\
        res = scanf(fmt, strval, &arg); \
        if (res != 1) {\
            puts("Format");\
            puts(fmt);\
            printf("Did not convert: %d\n", res);\
        } else if ((arg != exp) && (arg == arg || exp == exp)) { \
            puts("Format:"); \
            puts(fmt); \
            puts("Source:");\
            puts(src);\
            puts("Expected:");\
            printf(err, exp);\
            puts("Actual:");\
            printf(err, arg);\
            bad = 1;\
        }\
    } while(0)

int main(int argc, char *argv[]) {

    char *quit = (char *)(size_t)0xdead;
    int res = 0;
    int bad = 0;
    int bad_str = 0;

    char                charval = 0;
    unsigned char       ucharval = 0;
    short               shortval = 0;
    unsigned short      ushortval = 0;
    int                 intval = 0;
    unsigned int        uintval = 0;
    long                longval = 0;
    unsigned long       ulongval = 0;
    long long           longlongval = 0;
    unsigned long long  ulonglongval = 0;
    ssize_t             ssizeval = 0;
    size_t              sizeval = 0;
    float               floatval = 0;
    double              doubleval = 0;
    void               *ptrval = NULL;

    char                strval[16] = { 0 };

    FILE               *file = (FILE *)0x47492a00;
    
    TEST("%d", " 42", intval, (int)42, "%d\n");
 
    TEST("%hhd", "42", charval, (char)42, "%hhd\n");
    TEST("%hd", "42", shortval, (short)42, "%hd\n");
    TEST("%d", "42", intval, (int)42, "%d\n");
    TEST("%ld", "42", longval, (long)42, "%ld\n");
    TEST("%lld", "42", longlongval, (long long)42, "%lld\n");
    TEST("%zd", "42", ssizeval, (ssize_t)42, "%zd\n");
    
    TEST("%hhd", "-42", charval, (char)-42, "%d\n");
    TEST("%hd", "-42", shortval, (short)-42, "%hd\n");
    TEST("%d", "-42", intval, (int)-42, "%d\n");
    TEST("%ld", "-42", longval, (long)-42l, "%ld\n");
    TEST("%lld", "-42", longlongval, (long long)-42ll, "%lld\n");
    TEST("%zd", "-42", ssizeval, (ssize_t)-42l, "%zd\n");
    
    TEST("%hhd", "18446744073709551615", charval, (char)-1, "%hhd\n");
    TEST("%hd", "18446744073709551615", shortval, (short)-1, "%hd\n");
    TEST("%d", "18446744073709551615", intval, INTRES, "%d\n");
    TEST("%ld", "18446744073709551615", longval, (long)LONG_MAX, "%ld\n");
    TEST("%lld", "18446744073709551615", longlongval, (long long)LLONG_MAX, "%lld\n");
    TEST("%zd", "18446744073709551615", ssizeval, (ssize_t)LONG_MAX, "%zd\n");
    
    TEST("%o", " 52", uintval, 42, "%u\n");

    TEST("%hho", "52", ucharval, 42, "%hhu\n");
    TEST("%ho", "52", ushortval, 42, "%hu\n");
    TEST("%o", "52", uintval, 42, "%u\n");
    TEST("%lo", "52", ulongval, 42, "%lu\n");
    TEST("%llo", "52", ulonglongval, 42, "%llu\n");
    TEST("%zo", "52", sizeval, 42, "%zu\n");
    
    TEST("%hho", "1777777777777777777777", ucharval, UCHAR_MAX, "%hhu\n");
    TEST("%ho", "1777777777777777777777", ushortval, USHRT_MAX, "%hu\n");
    TEST("%o", "1777777777777777777777", uintval, UINT_MAX, "%u\n");
    TEST("%lo", "1777777777777777777777", ulongval, ULONG_MAX, "%lu\n");
    TEST("%llo", "1777777777777777777777", ulonglongval, ULLONG_MAX, "%llu\n");
    TEST("%zo", "1777777777777777777777", sizeval, ULONG_MAX, "%zu\n");
    
    TEST("%u", " 42", uintval, 42, "%u\n");
    
    TEST("%hhu", "42", ucharval, 42, "%hhu\n");
    TEST("%hu", "42", ushortval, 42, "%hu\n");
    TEST("%u", "42", uintval, 42, "%u\n");
    TEST("%lu", "42", ulongval, 42, "%lu\n");
    TEST("%llu", "42", ulonglongval, 42, "%llu\n");
    TEST("%zu", "42", sizeval, 42, "%zu\n");
    
    TEST("%hhu", "18446744073709551615", ucharval, UCHAR_MAX, "%hhu\n");
    TEST("%hu", "18446744073709551615", ushortval, USHRT_MAX, "%hu\n");
    TEST("%u", "18446744073709551615", uintval, UINT_MAX, "%u\n");
    TEST("%lu", "18446744073709551615", ulongval, ULONG_MAX, "%lu\n");
    TEST("%llu", "18446744073709551615", ulonglongval, ULLONG_MAX, "%llu\n");
    TEST("%zu", "18446744073709551615", sizeval, ULONG_MAX, "%zu\n");
    
    TEST("%f", " 42", floatval, 42.0, "%f\n");

    TEST("%f", "42", floatval, 42.0, "%f\n");
    TEST("%f", "+42", floatval, 42.0, "%f\n");
    TEST("%f", "42.0", floatval, 42.0, "%f\n");
    TEST("%f", "+42.0", floatval, 42.0, "%f\n");
    TEST("%f", "4.2e1", floatval, 42.0, "%f\n");
    TEST("%f", "+4.2e1", floatval, 42.0, "%f\n");
    TEST("%f", "4.2e+1", floatval, 42.0, "%f\n");
    TEST("%f", "+4.2e+1", floatval, 42.0, "%f\n");
    TEST("%f", "4.2E1", floatval, 42.0, "%f\n");
    TEST("%f", "+4.2E1", floatval, 42.0, "%f\n");
    TEST("%f", "4.2E+1", floatval, 42.0, "%f\n");
    TEST("%f", "+4.2E+1", floatval, 42.0, "%f\n");
    
    TEST("%f", "-42", floatval, -42.0, "%f\n");
    TEST("%f", "-42.0", floatval, -42.0, "%f\n");
    TEST("%f", "-4.2e1", floatval, -42.0, "%f\n");
    TEST("%f", "-4.2e+1", floatval, -42.0, "%f\n");
    TEST("%f", "-4.2E1", floatval, -42.0, "%f\n");
    TEST("%f", "-4.2E+1", floatval, -42.0, "%f\n");

    TEST("%f", "inf", floatval, INFINITY, "%f\n");
    TEST("%f", "infinity", floatval, INFINITY, "%f\n");
    TEST("%f", "INF", floatval, INFINITY, "%f\n");
    TEST("%f", "INFINITY", floatval, INFINITY, "%f\n");
    TEST("%f", "-inf", floatval, -INFINITY, "%f\n");
    TEST("%f", "-infinity", floatval, -INFINITY, "%f\n");
    TEST("%f", "-INF", floatval, -INFINITY, "%f\n");
    TEST("%f", "-INFINITY", floatval, -INFINITY, "%f\n");

    TEST("%f", "nan", floatval, NAN, "%f\n");
    TEST("%f", "NAN", floatval, NAN, "%f\n");
    TEST("%f", "-nan", floatval, -NAN, "%f\n");
    TEST("%f", "-NAN", floatval, -NAN, "%f\n");
    
    TEST("%lf", " 42", doubleval, 42.0, "%f\n");
    
    TEST("%lf", "42", doubleval, 42.0, "%f\n");
    TEST("%lf", "+42", doubleval, 42.0, "%f\n");
    TEST("%lf", "42.0", doubleval, 42.0, "%f\n");
    TEST("%lf", "+42.0", doubleval, 42.0, "%f\n");
    TEST("%lf", "4.2e1", doubleval, 42.0, "%f\n");
    TEST("%lf", "+4.2e1", doubleval, 42.0, "%f\n");
    TEST("%lf", "4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%lf", "+4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%lf", "4.2E1", doubleval, 42.0, "%f\n");
    TEST("%lf", "+4.2E1", doubleval, 42.0, "%f\n");
    TEST("%lf", "4.2E+1", doubleval, 42.0, "%f\n");
    TEST("%lf", "+4.2E+1", doubleval, 42.0, "%f\n");
    
    TEST("%lf", "-42", doubleval, -42.0, "%f\n");
    TEST("%lf", "-42.0", doubleval, -42.0, "%f\n");
    TEST("%lf", "-4.2e1", doubleval, -42.0, "%f\n");
    TEST("%lf", "-4.2e+1", doubleval, -42.0, "%f\n");
    TEST("%lf", "-4.2E1", doubleval, -42.0, "%f\n");
    TEST("%lf", "-4.2E+1", doubleval, -42.0, "%f\n");
    
    TEST("%lf", ".42", doubleval, 0.42, "%f\n");
    TEST("%lf", "+.42", doubleval, 0.42, "%f\n");
    TEST("%lf", "0.42", doubleval, 0.42, "%f\n");
    TEST("%lf", "+0.42", doubleval, 0.42, "%f\n");
    TEST("%lf", "4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%lf", "+4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%lf", "4.2E-1", doubleval, 0.42, "%f\n");
    TEST("%lf", "+4.2E-1", doubleval, 0.42, "%f\n");
    
    TEST("%lf", "inf", doubleval, INFINITY, "%f\n");
    TEST("%lf", "infinity", doubleval, INFINITY, "%f\n");
    TEST("%lf", "INF", doubleval, INFINITY, "%f\n");
    TEST("%lf", "INFINITY", doubleval, INFINITY, "%f\n");
    TEST("%lf", "-inf", doubleval, -INFINITY, "%f\n");
    TEST("%lf", "-infinity", doubleval, -INFINITY, "%f\n");
    TEST("%lf", "-INF", doubleval, -INFINITY, "%f\n");
    TEST("%lf", "-INFINITY", doubleval, -INFINITY, "%f\n");

    TEST("%lf", "nan", doubleval, NAN, "%f\n");
    TEST("%lf", "NAN", doubleval, NAN, "%f\n");
    TEST("%lf", "-nan", doubleval, -NAN, "%f\n");
    TEST("%lf", "-NAN", doubleval, -NAN, "%f\n");
    
    TEST("%e", " 42", floatval, 42.0, "%f\n");
    
    TEST("%e", "42", floatval, 42.0, "%f\n");
    TEST("%e", "+42", floatval, 42.0, "%f\n");
    TEST("%e", "42.0", floatval, 42.0, "%f\n");
    TEST("%e", "+42.0", floatval, 42.0, "%f\n");
    TEST("%e", "4.2e1", floatval, 42.0, "%f\n");
    TEST("%e", "+4.2e1", floatval, 42.0, "%f\n");
    TEST("%e", "4.2e+1", floatval, 42.0, "%f\n");
    TEST("%e", "+4.2e+1", floatval, 42.0, "%f\n");
    TEST("%e", "4.2E1", floatval, 42.0, "%f\n");
    TEST("%e", "+4.2E1", floatval, 42.0, "%f\n");
    TEST("%e", "4.2E+1", floatval, 42.0, "%f\n");
    TEST("%e", "+4.2E+1", floatval, 42.0, "%f\n");
    
    TEST("%e", "-42", floatval, -42.0, "%f\n");
    TEST("%e", "-42.0", floatval, -42.0, "%f\n");
    TEST("%e", "-4.2e1", floatval, -42.0, "%f\n");
    TEST("%e", "-4.2e+1", floatval, -42.0, "%f\n");
    TEST("%e", "-4.2E1", floatval, -42.0, "%f\n");
    TEST("%e", "-4.2E+1", floatval, -42.0, "%f\n");

    TEST("%e", "inf", floatval, INFINITY, "%f\n");
    TEST("%e", "infinity", floatval, INFINITY, "%f\n");
    TEST("%e", "INF", floatval, INFINITY, "%f\n");
    TEST("%e", "INFINITY", floatval, INFINITY, "%f\n");
    TEST("%e", "-inf", floatval, -INFINITY, "%f\n");
    TEST("%e", "-infinity", floatval, -INFINITY, "%f\n");
    TEST("%e", "-INF", floatval, -INFINITY, "%f\n");
    TEST("%e", "-INFINITY", floatval, -INFINITY, "%f\n");

    TEST("%e", "nan", floatval, NAN, "%f\n");
    TEST("%e", "NAN", floatval, NAN, "%f\n");
    TEST("%e", "-nan", floatval, -NAN, "%f\n");
    TEST("%e", "-NAN", floatval, -NAN, "%f\n");
    
    TEST("%le", " 42", doubleval, 42.0, "%f\n");
    
    TEST("%le", "42", doubleval, 42.0, "%f\n");
    TEST("%le", "+42", doubleval, 42.0, "%f\n");
    TEST("%le", "42.0", doubleval, 42.0, "%f\n");
    TEST("%le", "+42.0", doubleval, 42.0, "%f\n");
    TEST("%le", "4.2e1", doubleval, 42.0, "%f\n");
    TEST("%le", "+4.2e1", doubleval, 42.0, "%f\n");
    TEST("%le", "4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%le", "+4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%le", "4.2E1", doubleval, 42.0, "%f\n");
    TEST("%le", "+4.2E1", doubleval, 42.0, "%f\n");
    TEST("%le", "4.2E+1", doubleval, 42.0, "%f\n");
    TEST("%le", "+4.2E+1", doubleval, 42.0, "%f\n");
    
    TEST("%le", "-42", doubleval, -42.0, "%f\n");
    TEST("%le", "-42.0", doubleval, -42.0, "%f\n");
    TEST("%le", "-4.2e1", doubleval, -42.0, "%f\n");
    TEST("%le", "-4.2e+1", doubleval, -42.0, "%f\n");
    TEST("%le", "-4.2E1", doubleval, -42.0, "%f\n");
    TEST("%le", "-4.2E+1", doubleval, -42.0, "%f\n");
    
    TEST("%le", ".42", doubleval, 0.42, "%f\n");
    TEST("%le", "+.42", doubleval, 0.42, "%f\n");
    TEST("%le", "0.42", doubleval, 0.42, "%f\n");
    TEST("%le", "+0.42", doubleval, 0.42, "%f\n");
    TEST("%le", "4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%le", "+4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%le", "4.2E-1", doubleval, 0.42, "%f\n");
    TEST("%le", "+4.2E-1", doubleval, 0.42, "%f\n");
    
    TEST("%le", "inf", doubleval, INFINITY, "%f\n");
    TEST("%le", "infinity", doubleval, INFINITY, "%f\n");
    TEST("%le", "INF", doubleval, INFINITY, "%f\n");
    TEST("%le", "INFINITY", doubleval, INFINITY, "%f\n");
    TEST("%le", "-inf", doubleval, -INFINITY, "%f\n");
    TEST("%le", "-infinity", doubleval, -INFINITY, "%f\n");
    TEST("%le", "-INF", doubleval, -INFINITY, "%f\n");
    TEST("%le", "-INFINITY", doubleval, -INFINITY, "%f\n");

    TEST("%le", "nan", doubleval, NAN, "%f\n");
    TEST("%le", "NAN", doubleval, NAN, "%f\n");
    TEST("%le", "-nan", doubleval, -NAN, "%f\n");
    TEST("%le", "-NAN", doubleval, -NAN, "%f\n");
    
    TEST("%g", " 42", floatval, 42.0, "%f\n");
    
    TEST("%g", "42", floatval, 42.0, "%f\n");
    TEST("%g", "+42", floatval, 42.0, "%f\n");
    TEST("%g", "42.0", floatval, 42.0, "%f\n");
    TEST("%g", "+42.0", floatval, 42.0, "%f\n");
    TEST("%g", "4.2e1", floatval, 42.0, "%f\n");
    TEST("%g", "+4.2e1", floatval, 42.0, "%f\n");
    TEST("%g", "4.2e+1", floatval, 42.0, "%f\n");
    TEST("%g", "+4.2e+1", floatval, 42.0, "%f\n");
    TEST("%g", "4.2E1", floatval, 42.0, "%f\n");
    TEST("%g", "+4.2E1", floatval, 42.0, "%f\n");
    TEST("%g", "4.2E+1", floatval, 42.0, "%f\n");
    TEST("%g", "+4.2E+1", floatval, 42.0, "%f\n");
    
    TEST("%g", "-42", floatval, -42.0, "%f\n");
    TEST("%g", "-42.0", floatval, -42.0, "%f\n");
    TEST("%g", "-4.2e1", floatval, -42.0, "%f\n");
    TEST("%g", "-4.2e+1", floatval, -42.0, "%f\n");
    TEST("%g", "-4.2E1", floatval, -42.0, "%f\n");
    TEST("%g", "-4.2E+1", floatval, -42.0, "%f\n");

    TEST("%g", "inf", floatval, INFINITY, "%f\n");
    TEST("%g", "infinity", floatval, INFINITY, "%f\n");
    TEST("%g", "INF", floatval, INFINITY, "%f\n");
    TEST("%g", "INFINITY", floatval, INFINITY, "%f\n");
    TEST("%g", "-inf", floatval, -INFINITY, "%f\n");
    TEST("%g", "-infinity", floatval, -INFINITY, "%f\n");
    TEST("%g", "-INF", floatval, -INFINITY, "%f\n");
    TEST("%g", "-INFINITY", floatval, -INFINITY, "%f\n");

    TEST("%g", "nan", floatval, NAN, "%f\n");
    TEST("%g", "NAN", floatval, NAN, "%f\n");
    TEST("%g", "-nan", floatval, -NAN, "%f\n");
    TEST("%g", "-NAN", floatval, -NAN, "%f\n");
    
    TEST("%lg", " 42", doubleval, 42.0, "%f\n");
    
    TEST("%lg", "42", doubleval, 42.0, "%f\n");
    TEST("%lg", "+42", doubleval, 42.0, "%f\n");
    TEST("%lg", "42.0", doubleval, 42.0, "%f\n");
    TEST("%lg", "+42.0", doubleval, 42.0, "%f\n");
    TEST("%lg", "4.2e1", doubleval, 42.0, "%f\n");
    TEST("%lg", "+4.2e1", doubleval, 42.0, "%f\n");
    TEST("%lg", "4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%lg", "+4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%lg", "4.2E1", doubleval, 42.0, "%f\n");
    TEST("%lg", "+4.2E1", doubleval, 42.0, "%f\n");
    TEST("%lg", "4.2E+1", doubleval, 42.0, "%f\n");
    TEST("%lg", "+4.2E+1", doubleval, 42.0, "%f\n");
    
    TEST("%lg", "-42", doubleval, -42.0, "%f\n");
    TEST("%lg", "-42.0", doubleval, -42.0, "%f\n");
    TEST("%lg", "-4.2e1", doubleval, -42.0, "%f\n");
    TEST("%lg", "-4.2e+1", doubleval, -42.0, "%f\n");
    TEST("%lg", "-4.2E1", doubleval, -42.0, "%f\n");
    TEST("%lg", "-4.2E+1", doubleval, -42.0, "%f\n");
    
    TEST("%lg", ".42", doubleval, 0.42, "%f\n");
    TEST("%lg", "+.42", doubleval, 0.42, "%f\n");
    TEST("%lg", "0.42", doubleval, 0.42, "%f\n");
    TEST("%lg", "+0.42", doubleval, 0.42, "%f\n");
    TEST("%lg", "4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%lg", "+4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%lg", "4.2E-1", doubleval, 0.42, "%f\n");
    TEST("%lg", "+4.2E-1", doubleval, 0.42, "%f\n");
    
    TEST("%lg", "inf", doubleval, INFINITY, "%f\n");
    TEST("%lg", "infinity", doubleval, INFINITY, "%f\n");
    TEST("%lg", "INF", doubleval, INFINITY, "%f\n");
    TEST("%lg", "INFINITY", doubleval, INFINITY, "%f\n");
    TEST("%lg", "-inf", doubleval, -INFINITY, "%f\n");
    TEST("%lg", "-infinity", doubleval, -INFINITY, "%f\n");
    TEST("%lg", "-INF", doubleval, -INFINITY, "%f\n");
    TEST("%lg", "-INFINITY", doubleval, -INFINITY, "%f\n");

    TEST("%lg", "nan", doubleval, NAN, "%f\n");
    TEST("%lg", "NAN", doubleval, NAN, "%f\n");
    TEST("%lg", "-nan", doubleval, -NAN, "%f\n");
    TEST("%lg", "-NAN", doubleval, -NAN, "%f\n");
    
    TEST("%E", " 42", floatval, 42.0, "%f\n");
    
    TEST("%E", "42", floatval, 42.0, "%f\n");
    TEST("%E", "+42", floatval, 42.0, "%f\n");
    TEST("%E", "42.0", floatval, 42.0, "%f\n");
    TEST("%E", "+42.0", floatval, 42.0, "%f\n");
    TEST("%E", "4.2e1", floatval, 42.0, "%f\n");
    TEST("%E", "+4.2e1", floatval, 42.0, "%f\n");
    TEST("%E", "4.2e+1", floatval, 42.0, "%f\n");
    TEST("%E", "+4.2e+1", floatval, 42.0, "%f\n");
    TEST("%E", "4.2E1", floatval, 42.0, "%f\n");
    TEST("%E", "+4.2E1", floatval, 42.0, "%f\n");
    TEST("%E", "4.2E+1", floatval, 42.0, "%f\n");
    TEST("%E", "+4.2E+1", floatval, 42.0, "%f\n");
    
    TEST("%E", "-42", floatval, -42.0, "%f\n");
    TEST("%E", "-42.0", floatval, -42.0, "%f\n");
    TEST("%E", "-4.2e1", floatval, -42.0, "%f\n");
    TEST("%E", "-4.2e+1", floatval, -42.0, "%f\n");
    TEST("%E", "-4.2E1", floatval, -42.0, "%f\n");
    TEST("%E", "-4.2E+1", floatval, -42.0, "%f\n");

    TEST("%E", "inf", floatval, INFINITY, "%f\n");
    TEST("%E", "infinity", floatval, INFINITY, "%f\n");
    TEST("%E", "INF", floatval, INFINITY, "%f\n");
    TEST("%E", "INFINITY", floatval, INFINITY, "%f\n");
    TEST("%E", "-inf", floatval, -INFINITY, "%f\n");
    TEST("%E", "-infinity", floatval, -INFINITY, "%f\n");
    TEST("%E", "-INF", floatval, -INFINITY, "%f\n");
    TEST("%E", "-INFINITY", floatval, -INFINITY, "%f\n");

    TEST("%E", "nan", floatval, NAN, "%f\n");
    TEST("%E", "NAN", floatval, NAN, "%f\n");
    TEST("%E", "-nan", floatval, -NAN, "%f\n");
    TEST("%E", "-NAN", floatval, -NAN, "%f\n");
    
    TEST("%lE", " 42", doubleval, 42.0, "%f\n");
    
    TEST("%lE", "42", doubleval, 42.0, "%f\n");
    TEST("%lE", "+42", doubleval, 42.0, "%f\n");
    TEST("%lE", "42.0", doubleval, 42.0, "%f\n");
    TEST("%lE", "+42.0", doubleval, 42.0, "%f\n");
    TEST("%lE", "4.2e1", doubleval, 42.0, "%f\n");
    TEST("%lE", "+4.2e1", doubleval, 42.0, "%f\n");
    TEST("%lE", "4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%lE", "+4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%lE", "4.2E1", doubleval, 42.0, "%f\n");
    TEST("%lE", "+4.2E1", doubleval, 42.0, "%f\n");
    TEST("%lE", "4.2E+1", doubleval, 42.0, "%f\n");
    TEST("%lE", "+4.2E+1", doubleval, 42.0, "%f\n");
    
    TEST("%lE", "-42", doubleval, -42.0, "%f\n");
    TEST("%lE", "-42.0", doubleval, -42.0, "%f\n");
    TEST("%lE", "-4.2e1", doubleval, -42.0, "%f\n");
    TEST("%lE", "-4.2e+1", doubleval, -42.0, "%f\n");
    TEST("%lE", "-4.2E1", doubleval, -42.0, "%f\n");
    TEST("%lE", "-4.2E+1", doubleval, -42.0, "%f\n");
    
    TEST("%lE", ".42", doubleval, 0.42, "%f\n");
    TEST("%lE", "+.42", doubleval, 0.42, "%f\n");
    TEST("%lE", "0.42", doubleval, 0.42, "%f\n");
    TEST("%lE", "+0.42", doubleval, 0.42, "%f\n");
    TEST("%lE", "4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%lE", "+4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%lE", "4.2E-1", doubleval, 0.42, "%f\n");
    TEST("%lE", "+4.2E-1", doubleval, 0.42, "%f\n");
    
    TEST("%lE", "inf", doubleval, INFINITY, "%f\n");
    TEST("%lE", "infinity", doubleval, INFINITY, "%f\n");
    TEST("%lE", "INF", doubleval, INFINITY, "%f\n");
    TEST("%lE", "INFINITY", doubleval, INFINITY, "%f\n");
    TEST("%lE", "-inf", doubleval, -INFINITY, "%f\n");
    TEST("%lE", "-infinity", doubleval, -INFINITY, "%f\n");
    TEST("%lE", "-INF", doubleval, -INFINITY, "%f\n");
    TEST("%lE", "-INFINITY", doubleval, -INFINITY, "%f\n");

    TEST("%lE", "nan", doubleval, NAN, "%f\n");
    TEST("%lE", "NAN", doubleval, NAN, "%f\n");
    TEST("%lE", "-nan", doubleval, -NAN, "%f\n");
    TEST("%lE", "-NAN", doubleval, -NAN, "%f\n");
    
    TEST("%a", "42", floatval, 42.0, "%f\n");
    TEST("%a", "+42", floatval, 42.0, "%f\n");
    TEST("%a", "42.0", floatval, 42.0, "%f\n");
    TEST("%a", "+42.0", floatval, 42.0, "%f\n");
    TEST("%a", "4.2e1", floatval, 42.0, "%f\n");
    TEST("%a", "+4.2e1", floatval, 42.0, "%f\n");
    TEST("%a", "4.2e+1", floatval, 42.0, "%f\n");
    TEST("%a", "+4.2e+1", floatval, 42.0, "%f\n");
    TEST("%a", "4.2E1", floatval, 42.0, "%f\n");
    TEST("%a", "+4.2E1", floatval, 42.0, "%f\n");
    TEST("%a", "4.2E+1", floatval, 42.0, "%f\n");
    TEST("%a", "+4.2E+1", floatval, 42.0, "%f\n");
    
    TEST("%a", "-42", floatval, -42.0, "%f\n");
    TEST("%a", "-42.0", floatval, -42.0, "%f\n");
    TEST("%a", "-4.2e1", floatval, -42.0, "%f\n");
    TEST("%a", "-4.2e+1", floatval, -42.0, "%f\n");
    TEST("%a", "-4.2E1", floatval, -42.0, "%f\n");
    TEST("%a", "-4.2E+1", floatval, -42.0, "%f\n");

    TEST("%a", "inf", floatval, INFINITY, "%f\n");
    TEST("%a", "infinity", floatval, INFINITY, "%f\n");
    TEST("%a", "INF", floatval, INFINITY, "%f\n");
    TEST("%a", "INFINITY", floatval, INFINITY, "%f\n");
    TEST("%a", "-inf", floatval, -INFINITY, "%f\n");
    TEST("%a", "-infinity", floatval, -INFINITY, "%f\n");
    TEST("%a", "-INF", floatval, -INFINITY, "%f\n");
    TEST("%a", "-INFINITY", floatval, -INFINITY, "%f\n");

    TEST("%a", "nan", floatval, NAN, "%f\n");
    TEST("%a", "NAN", floatval, NAN, "%f\n");
    TEST("%a", "-nan", floatval, -NAN, "%f\n");
    TEST("%a", "-NAN", floatval, -NAN, "%f\n");
    
    TEST("%la", "42", doubleval, 42.0, "%f\n");
    TEST("%la", "+42", doubleval, 42.0, "%f\n");
    TEST("%la", "42.0", doubleval, 42.0, "%f\n");
    TEST("%la", "+42.0", doubleval, 42.0, "%f\n");
    TEST("%la", "4.2e1", doubleval, 42.0, "%f\n");
    TEST("%la", "+4.2e1", doubleval, 42.0, "%f\n");
    TEST("%la", "4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%la", "+4.2e+1", doubleval, 42.0, "%f\n");
    TEST("%la", "4.2E1", doubleval, 42.0, "%f\n");
    TEST("%la", "+4.2E1", doubleval, 42.0, "%f\n");
    TEST("%la", "4.2E+1", doubleval, 42.0, "%f\n");
    TEST("%la", "+4.2E+1", doubleval, 42.0, "%f\n");
    
    TEST("%la", "-42", doubleval, -42.0, "%f\n");
    TEST("%la", "-42.0", doubleval, -42.0, "%f\n");
    TEST("%la", "-4.2e1", doubleval, -42.0, "%f\n");
    TEST("%la", "-4.2e+1", doubleval, -42.0, "%f\n");
    TEST("%la", "-4.2E1", doubleval, -42.0, "%f\n");
    TEST("%la", "-4.2E+1", doubleval, -42.0, "%f\n");
    
    TEST("%la", ".42", doubleval, 0.42, "%f\n");
    TEST("%la", "+.42", doubleval, 0.42, "%f\n");
    TEST("%la", "0.42", doubleval, 0.42, "%f\n");
    TEST("%la", "+0.42", doubleval, 0.42, "%f\n");
    TEST("%la", "4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%la", "+4.2e-1", doubleval, 0.42, "%f\n");
    TEST("%la", "4.2E-1", doubleval, 0.42, "%f\n");
    TEST("%la", "+4.2E-1", doubleval, 0.42, "%f\n");
    
    TEST("%la", "inf", doubleval, INFINITY, "%f\n");
    TEST("%la", "infinity", doubleval, INFINITY, "%f\n");
    TEST("%la", "INF", doubleval, INFINITY, "%f\n");
    TEST("%la", "INFINITY", doubleval, INFINITY, "%f\n");
    TEST("%la", "-inf", doubleval, -INFINITY, "%f\n");
    TEST("%la", "-infinity", doubleval, -INFINITY, "%f\n");
    TEST("%la", "-INF", doubleval, -INFINITY, "%f\n");
    TEST("%la", "-INFINITY", doubleval, -INFINITY, "%f\n");

    TEST("%la", "nan", doubleval, NAN, "%f\n");
    TEST("%la", "NAN", doubleval, NAN, "%f\n");
    TEST("%la", "-nan", doubleval, -NAN, "%f\n");
    TEST("%la", "-NAN", doubleval, -NAN, "%f\n");
    
    TEST("%f", "4e", floatval, 4.0, "%f\n");

    TEST("%p", "(nil)", ptrval, NULL, "%p\n");
    TEST("%p", "(NIL)", ptrval, NULL, "%p\n");
    TEST("%p", "abcd42", ptrval, (void *)0xabcd42, "%p\n");
    TEST("%p", "0xabcd42", ptrval, (void *)0xabcd42, "%p\n");

    TEST_STR("%10c", "foo", strval, "foo", 0);
    TEST_STR("%3c", "foobar", strval, "foo", 3);

    TEST_STR("%s", "foo", strval, "foo", 0);
    TEST_STR("%s", " foo", strval, "foo", 0);
    TEST_STR("%3s", "foobar", strval, "foo", 3);

    TEST_LEN("%s%n", "foobar", intval, 6, "%d\n");

    if(bad) {
        return 1;
    }
    puts("SUCCESS!");
    return *quit;
}            
