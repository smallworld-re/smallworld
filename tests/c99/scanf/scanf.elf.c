#include <limits.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

#if __WORDSIZE == 64
#define INTRES -1
#else
#define INTRES 2147483647
#endif

#define xstr(s) #s
#define str(s) xstr(s)

#define MY_ISNAN(x) (((x >> ((sizeof(x) * 8) - 12)) & 0x7f8ll) == (0x7f8))

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

// Macros for testing floats
// I am not putting up with the noise
// that is floating-point equality.
#define TEST_FLOAT(fmt, src, arg, exp) \
    do {\
        for(int i = strlen(src) - 1; i >= 0; i--) {\
            ungetc(src[i], file);\
        }\
        res = scanf(fmt, &arg); \
        float_tmp = exp;\
        float_exp = *((int *)(void *)(&float_tmp));\
        float_arg = *((int *)(void *)(&arg));\
        if (res != 1) {\
            puts("Format:");\
            puts(fmt);\
            puts("Source:");\
            puts(src);\
            printf("Did not convert: %d\n", res);\
            bad = 1; \
        } else if (MY_ISNAN(float_exp) && MY_ISNAN(float_arg)) {\
        } else if (float_arg != float_exp) { \
            puts("Format:"); \
            puts(fmt); \
            puts("Source:");\
            puts(src);\
            puts("Expected:");\
            printf("%f (%llx)\n", exp, float_exp);\
            puts("Actual:");\
            printf("%f (%llx)\n", arg, float_arg);\
            bad = 1;\
        }\
    } while(0)

#define TEST_DOUBLE(fmt, src, arg, exp) \
    do {\
        for(int i = strlen(src) - 1; i >= 0; i--) {\
            ungetc(src[i], file);\
        }\
        res = scanf(fmt, &arg); \
        double_tmp = exp;\
        double_exp = *((long long *)(void *)(&double_tmp));\
        double_arg = *((long long *)(void *)(&arg));\
        if (res != 1) {\
            puts("Format:");\
            puts(fmt);\
            puts("Source:");\
            puts(src);\
            printf("Did not convert: %d\n", res);\
            bad = 1;\
        } else if (MY_ISNAN(double_exp) && MY_ISNAN(double_arg)) {\
        } else if (double_arg != double_exp) { \
            puts("Format:"); \
            puts(fmt); \
            puts("Source:");\
            puts(src);\
            puts("Expected:");\
            printf("%f (%llx)\n", exp, double_exp);\
            puts("Actual:");\
            printf("%f (%llx)\n", arg, double_arg);\
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
            puts("Format:");\
            puts(fmt);\
            puts("Source:");\
            puts(src);\
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

int main() {

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
    
    float               float_tmp = 0ll;
    int                 float_exp = 0ll;
    int                 float_arg = 0ll;
    
    double              double_tmp = 0ll;
    long long           double_exp = 0ll;
    long long           double_arg = 0ll;

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
    
    TEST_FLOAT("%f", " 42", floatval, 42.0);

    TEST_FLOAT("%f", "42", floatval, 42.0);
    TEST_FLOAT("%f", "+42", floatval, 42.0);
    TEST_FLOAT("%f", "42.0", floatval, 42.0);
    TEST_FLOAT("%f", "+42.0", floatval, 42.0);
    TEST_FLOAT("%f", "4.2e1", floatval, 42.0);
    TEST_FLOAT("%f", "+4.2e1", floatval, 42.0);
    TEST_FLOAT("%f", "4.2e+1", floatval, 42.0);
    TEST_FLOAT("%f", "+4.2e+1", floatval, 42.0);
    TEST_FLOAT("%f", "4.2E1", floatval, 42.0);
    TEST_FLOAT("%f", "+4.2E1", floatval, 42.0);
    TEST_FLOAT("%f", "4.2E+1", floatval, 42.0);
    TEST_FLOAT("%f", "+4.2E+1", floatval, 42.0);
    
    TEST_FLOAT("%f", "-42", floatval, -42.0);
    TEST_FLOAT("%f", "-42.0", floatval, -42.0);
    TEST_FLOAT("%f", "-4.2e1", floatval, -42.0);
    TEST_FLOAT("%f", "-4.2e+1", floatval, -42.0);
    TEST_FLOAT("%f", "-4.2E1", floatval, -42.0);
    TEST_FLOAT("%f", "-4.2E+1", floatval, -42.0);

    TEST_FLOAT("%f", "inf", floatval, INFINITY);
    TEST_FLOAT("%f", "infinity", floatval, INFINITY);
    TEST_FLOAT("%f", "INF", floatval, INFINITY);
    TEST_FLOAT("%f", "INFINITY", floatval, INFINITY);
    TEST_FLOAT("%f", "-inf", floatval, -INFINITY);
    TEST_FLOAT("%f", "-infinity", floatval, -INFINITY);
    TEST_FLOAT("%f", "-INF", floatval, -INFINITY);
    TEST_FLOAT("%f", "-INFINITY", floatval, -INFINITY);

    TEST_FLOAT("%f", "nan", floatval, NAN);
    TEST_FLOAT("%f", "NAN", floatval, NAN);
    TEST_FLOAT("%f", "-nan", floatval, -NAN);
    TEST_FLOAT("%f", "-NAN", floatval, -NAN);
    
    TEST_DOUBLE("%lf", " 42", doubleval, 42.0);
    
    TEST_DOUBLE("%lf", "42", doubleval, 42.0);
    TEST_DOUBLE("%lf", "+42", doubleval, 42.0);
    TEST_DOUBLE("%lf", "42.0", doubleval, 42.0);
    TEST_DOUBLE("%lf", "+42.0", doubleval, 42.0);
    TEST_DOUBLE("%lf", "4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%lf", "+4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%lf", "4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%lf", "+4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%lf", "4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%lf", "+4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%lf", "4.2E+1", doubleval, 42.0);
    TEST_DOUBLE("%lf", "+4.2E+1", doubleval, 42.0);
    
    TEST_DOUBLE("%lf", "-42", doubleval, -42.0);
    TEST_DOUBLE("%lf", "-42.0", doubleval, -42.0);
    TEST_DOUBLE("%lf", "-4.2e1", doubleval, -42.0);
    TEST_DOUBLE("%lf", "-4.2e+1", doubleval, -42.0);
    TEST_DOUBLE("%lf", "-4.2E1", doubleval, -42.0);
    TEST_DOUBLE("%lf", "-4.2E+1", doubleval, -42.0);
    
    TEST_DOUBLE("%lf", ".42", doubleval, 0.42);
    TEST_DOUBLE("%lf", "+.42", doubleval, 0.42);
    TEST_DOUBLE("%lf", "0.42", doubleval, 0.42);
    TEST_DOUBLE("%lf", "+0.42", doubleval, 0.42);
    TEST_DOUBLE("%lf", "4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%lf", "+4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%lf", "4.2E-1", doubleval, 0.42);
    TEST_DOUBLE("%lf", "+4.2E-1", doubleval, 0.42);
    
    TEST_DOUBLE("%lf", "inf", doubleval, INFINITY);
    TEST_DOUBLE("%lf", "infinity", doubleval, INFINITY);
    TEST_DOUBLE("%lf", "INF", doubleval, INFINITY);
    TEST_DOUBLE("%lf", "INFINITY", doubleval, INFINITY);
    TEST_DOUBLE("%lf", "-inf", doubleval, -INFINITY);
    TEST_DOUBLE("%lf", "-infinity", doubleval, -INFINITY);
    TEST_DOUBLE("%lf", "-INF", doubleval, -INFINITY);
    TEST_DOUBLE("%lf", "-INFINITY", doubleval, -INFINITY);

    TEST_DOUBLE("%lf", "nan", doubleval, NAN);
    TEST_DOUBLE("%lf", "NAN", doubleval, NAN);
    TEST_DOUBLE("%lf", "-nan", doubleval, -NAN);
    TEST_DOUBLE("%lf", "-NAN", doubleval, -NAN);
    
    TEST_FLOAT("%e", " 42", floatval, 42.0);
    
    TEST_FLOAT("%e", "42", floatval, 42.0);
    TEST_FLOAT("%e", "+42", floatval, 42.0);
    TEST_FLOAT("%e", "42.0", floatval, 42.0);
    TEST_FLOAT("%e", "+42.0", floatval, 42.0);
    TEST_FLOAT("%e", "4.2e1", floatval, 42.0);
    TEST_FLOAT("%e", "+4.2e1", floatval, 42.0);
    TEST_FLOAT("%e", "4.2e+1", floatval, 42.0);
    TEST_FLOAT("%e", "+4.2e+1", floatval, 42.0);
    TEST_FLOAT("%e", "4.2E1", floatval, 42.0);
    TEST_FLOAT("%e", "+4.2E1", floatval, 42.0);
    TEST_FLOAT("%e", "4.2E+1", floatval, 42.0);
    TEST_FLOAT("%e", "+4.2E+1", floatval, 42.0);
    
    TEST_FLOAT("%e", "-42", floatval, -42.0);
    TEST_FLOAT("%e", "-42.0", floatval, -42.0);
    TEST_FLOAT("%e", "-4.2e1", floatval, -42.0);
    TEST_FLOAT("%e", "-4.2e+1", floatval, -42.0);
    TEST_FLOAT("%e", "-4.2E1", floatval, -42.0);
    TEST_FLOAT("%e", "-4.2E+1", floatval, -42.0);

    TEST_FLOAT("%e", "inf", floatval, INFINITY);
    TEST_FLOAT("%e", "infinity", floatval, INFINITY);
    TEST_FLOAT("%e", "INF", floatval, INFINITY);
    TEST_FLOAT("%e", "INFINITY", floatval, INFINITY);
    TEST_FLOAT("%e", "-inf", floatval, -INFINITY);
    TEST_FLOAT("%e", "-infinity", floatval, -INFINITY);
    TEST_FLOAT("%e", "-INF", floatval, -INFINITY);
    TEST_FLOAT("%e", "-INFINITY", floatval, -INFINITY);

    TEST_FLOAT("%e", "nan", floatval, NAN);
    TEST_FLOAT("%e", "NAN", floatval, NAN);
    TEST_FLOAT("%e", "-nan", floatval, -NAN);
    TEST_FLOAT("%e", "-NAN", floatval, -NAN);
    
    TEST_DOUBLE("%le", " 42", doubleval, 42.0);
    
    TEST_DOUBLE("%le", "42", doubleval, 42.0);
    TEST_DOUBLE("%le", "+42", doubleval, 42.0);
    TEST_DOUBLE("%le", "42.0", doubleval, 42.0);
    TEST_DOUBLE("%le", "+42.0", doubleval, 42.0);
    TEST_DOUBLE("%le", "4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%le", "+4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%le", "4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%le", "+4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%le", "4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%le", "+4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%le", "4.2E+1", doubleval, 42.0);
    TEST_DOUBLE("%le", "+4.2E+1", doubleval, 42.0);
    
    TEST_DOUBLE("%le", "-42", doubleval, -42.0);
    TEST_DOUBLE("%le", "-42.0", doubleval, -42.0);
    TEST_DOUBLE("%le", "-4.2e1", doubleval, -42.0);
    TEST_DOUBLE("%le", "-4.2e+1", doubleval, -42.0);
    TEST_DOUBLE("%le", "-4.2E1", doubleval, -42.0);
    TEST_DOUBLE("%le", "-4.2E+1", doubleval, -42.0);
    
    TEST_DOUBLE("%le", ".42", doubleval, 0.42);
    TEST_DOUBLE("%le", "+.42", doubleval, 0.42);
    TEST_DOUBLE("%le", "0.42", doubleval, 0.42);
    TEST_DOUBLE("%le", "+0.42", doubleval, 0.42);
    TEST_DOUBLE("%le", "4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%le", "+4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%le", "4.2E-1", doubleval, 0.42);
    TEST_DOUBLE("%le", "+4.2E-1", doubleval, 0.42);
    
    TEST_DOUBLE("%le", "inf", doubleval, INFINITY);
    TEST_DOUBLE("%le", "infinity", doubleval, INFINITY);
    TEST_DOUBLE("%le", "INF", doubleval, INFINITY);
    TEST_DOUBLE("%le", "INFINITY", doubleval, INFINITY);
    TEST_DOUBLE("%le", "-inf", doubleval, -INFINITY);
    TEST_DOUBLE("%le", "-infinity", doubleval, -INFINITY);
    TEST_DOUBLE("%le", "-INF", doubleval, -INFINITY);
    TEST_DOUBLE("%le", "-INFINITY", doubleval, -INFINITY);

    TEST_DOUBLE("%le", "nan", doubleval, NAN);
    TEST_DOUBLE("%le", "NAN", doubleval, NAN);
    TEST_DOUBLE("%le", "-nan", doubleval, -NAN);
    TEST_DOUBLE("%le", "-NAN", doubleval, -NAN);
    
    TEST_FLOAT("%g", " 42", floatval, 42.0);
    
    TEST_FLOAT("%g", "42", floatval, 42.0);
    TEST_FLOAT("%g", "+42", floatval, 42.0);
    TEST_FLOAT("%g", "42.0", floatval, 42.0);
    TEST_FLOAT("%g", "+42.0", floatval, 42.0);
    TEST_FLOAT("%g", "4.2e1", floatval, 42.0);
    TEST_FLOAT("%g", "+4.2e1", floatval, 42.0);
    TEST_FLOAT("%g", "4.2e+1", floatval, 42.0);
    TEST_FLOAT("%g", "+4.2e+1", floatval, 42.0);
    TEST_FLOAT("%g", "4.2E1", floatval, 42.0);
    TEST_FLOAT("%g", "+4.2E1", floatval, 42.0);
    TEST_FLOAT("%g", "4.2E+1", floatval, 42.0);
    TEST_FLOAT("%g", "+4.2E+1", floatval, 42.0);
    
    TEST_FLOAT("%g", "-42", floatval, -42.0);
    TEST_FLOAT("%g", "-42.0", floatval, -42.0);
    TEST_FLOAT("%g", "-4.2e1", floatval, -42.0);
    TEST_FLOAT("%g", "-4.2e+1", floatval, -42.0);
    TEST_FLOAT("%g", "-4.2E1", floatval, -42.0);
    TEST_FLOAT("%g", "-4.2E+1", floatval, -42.0);

    TEST_FLOAT("%g", "inf", floatval, INFINITY);
    TEST_FLOAT("%g", "infinity", floatval, INFINITY);
    TEST_FLOAT("%g", "INF", floatval, INFINITY);
    TEST_FLOAT("%g", "INFINITY", floatval, INFINITY);
    TEST_FLOAT("%g", "-inf", floatval, -INFINITY);
    TEST_FLOAT("%g", "-infinity", floatval, -INFINITY);
    TEST_FLOAT("%g", "-INF", floatval, -INFINITY);
    TEST_FLOAT("%g", "-INFINITY", floatval, -INFINITY);

    TEST_FLOAT("%g", "nan", floatval, NAN);
    TEST_FLOAT("%g", "NAN", floatval, NAN);
    TEST_FLOAT("%g", "-nan", floatval, -NAN);
    TEST_FLOAT("%g", "-NAN", floatval, -NAN);
    
    TEST_DOUBLE("%lg", " 42", doubleval, 42.0);
    
    TEST_DOUBLE("%lg", "42", doubleval, 42.0);
    TEST_DOUBLE("%lg", "+42", doubleval, 42.0);
    TEST_DOUBLE("%lg", "42.0", doubleval, 42.0);
    TEST_DOUBLE("%lg", "+42.0", doubleval, 42.0);
    TEST_DOUBLE("%lg", "4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%lg", "+4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%lg", "4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%lg", "+4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%lg", "4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%lg", "+4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%lg", "4.2E+1", doubleval, 42.0);
    TEST_DOUBLE("%lg", "+4.2E+1", doubleval, 42.0);
    
    TEST_DOUBLE("%lg", "-42", doubleval, -42.0);
    TEST_DOUBLE("%lg", "-42.0", doubleval, -42.0);
    TEST_DOUBLE("%lg", "-4.2e1", doubleval, -42.0);
    TEST_DOUBLE("%lg", "-4.2e+1", doubleval, -42.0);
    TEST_DOUBLE("%lg", "-4.2E1", doubleval, -42.0);
    TEST_DOUBLE("%lg", "-4.2E+1", doubleval, -42.0);
    
    TEST_DOUBLE("%lg", ".42", doubleval, 0.42);
    TEST_DOUBLE("%lg", "+.42", doubleval, 0.42);
    TEST_DOUBLE("%lg", "0.42", doubleval, 0.42);
    TEST_DOUBLE("%lg", "+0.42", doubleval, 0.42);
    TEST_DOUBLE("%lg", "4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%lg", "+4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%lg", "4.2E-1", doubleval, 0.42);
    TEST_DOUBLE("%lg", "+4.2E-1", doubleval, 0.42);
    
    TEST_DOUBLE("%lg", "inf", doubleval, INFINITY);
    TEST_DOUBLE("%lg", "infinity", doubleval, INFINITY);
    TEST_DOUBLE("%lg", "INF", doubleval, INFINITY);
    TEST_DOUBLE("%lg", "INFINITY", doubleval, INFINITY);
    TEST_DOUBLE("%lg", "-inf", doubleval, -INFINITY);
    TEST_DOUBLE("%lg", "-infinity", doubleval, -INFINITY);
    TEST_DOUBLE("%lg", "-INF", doubleval, -INFINITY);
    TEST_DOUBLE("%lg", "-INFINITY", doubleval, -INFINITY);

    TEST_DOUBLE("%lg", "nan", doubleval, NAN);
    TEST_DOUBLE("%lg", "NAN", doubleval, NAN);
    TEST_DOUBLE("%lg", "-nan", doubleval, -NAN);
    TEST_DOUBLE("%lg", "-NAN", doubleval, -NAN);
    
    TEST_FLOAT("%E", " 42", floatval, 42.0);
    
    TEST_FLOAT("%E", "42", floatval, 42.0);
    TEST_FLOAT("%E", "+42", floatval, 42.0);
    TEST_FLOAT("%E", "42.0", floatval, 42.0);
    TEST_FLOAT("%E", "+42.0", floatval, 42.0);
    TEST_FLOAT("%E", "4.2e1", floatval, 42.0);
    TEST_FLOAT("%E", "+4.2e1", floatval, 42.0);
    TEST_FLOAT("%E", "4.2e+1", floatval, 42.0);
    TEST_FLOAT("%E", "+4.2e+1", floatval, 42.0);
    TEST_FLOAT("%E", "4.2E1", floatval, 42.0);
    TEST_FLOAT("%E", "+4.2E1", floatval, 42.0);
    TEST_FLOAT("%E", "4.2E+1", floatval, 42.0);
    TEST_FLOAT("%E", "+4.2E+1", floatval, 42.0);
    
    TEST_FLOAT("%E", "-42", floatval, -42.0);
    TEST_FLOAT("%E", "-42.0", floatval, -42.0);
    TEST_FLOAT("%E", "-4.2e1", floatval, -42.0);
    TEST_FLOAT("%E", "-4.2e+1", floatval, -42.0);
    TEST_FLOAT("%E", "-4.2E1", floatval, -42.0);
    TEST_FLOAT("%E", "-4.2E+1", floatval, -42.0);

    TEST_FLOAT("%E", "inf", floatval, INFINITY);
    TEST_FLOAT("%E", "infinity", floatval, INFINITY);
    TEST_FLOAT("%E", "INF", floatval, INFINITY);
    TEST_FLOAT("%E", "INFINITY", floatval, INFINITY);
    TEST_FLOAT("%E", "-inf", floatval, -INFINITY);
    TEST_FLOAT("%E", "-infinity", floatval, -INFINITY);
    TEST_FLOAT("%E", "-INF", floatval, -INFINITY);
    TEST_FLOAT("%E", "-INFINITY", floatval, -INFINITY);

    TEST_FLOAT("%E", "nan", floatval, NAN);
    TEST_FLOAT("%E", "NAN", floatval, NAN);
    TEST_FLOAT("%E", "-nan", floatval, -NAN);
    TEST_FLOAT("%E", "-NAN", floatval, -NAN);
    
    TEST_DOUBLE("%lE", " 42", doubleval, 42.0);
    
    TEST_DOUBLE("%lE", "42", doubleval, 42.0);
    TEST_DOUBLE("%lE", "+42", doubleval, 42.0);
    TEST_DOUBLE("%lE", "42.0", doubleval, 42.0);
    TEST_DOUBLE("%lE", "+42.0", doubleval, 42.0);
    TEST_DOUBLE("%lE", "4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%lE", "+4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%lE", "4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%lE", "+4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%lE", "4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%lE", "+4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%lE", "4.2E+1", doubleval, 42.0);
    TEST_DOUBLE("%lE", "+4.2E+1", doubleval, 42.0);
    
    TEST_DOUBLE("%lE", "-42", doubleval, -42.0);
    TEST_DOUBLE("%lE", "-42.0", doubleval, -42.0);
    TEST_DOUBLE("%lE", "-4.2e1", doubleval, -42.0);
    TEST_DOUBLE("%lE", "-4.2e+1", doubleval, -42.0);
    TEST_DOUBLE("%lE", "-4.2E1", doubleval, -42.0);
    TEST_DOUBLE("%lE", "-4.2E+1", doubleval, -42.0);
    
    TEST_DOUBLE("%lE", ".42", doubleval, 0.42);
    TEST_DOUBLE("%lE", "+.42", doubleval, 0.42);
    TEST_DOUBLE("%lE", "0.42", doubleval, 0.42);
    TEST_DOUBLE("%lE", "+0.42", doubleval, 0.42);
    TEST_DOUBLE("%lE", "4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%lE", "+4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%lE", "4.2E-1", doubleval, 0.42);
    TEST_DOUBLE("%lE", "+4.2E-1", doubleval, 0.42);
    
    TEST_DOUBLE("%lE", "inf", doubleval, INFINITY);
    TEST_DOUBLE("%lE", "infinity", doubleval, INFINITY);
    TEST_DOUBLE("%lE", "INF", doubleval, INFINITY);
    TEST_DOUBLE("%lE", "INFINITY", doubleval, INFINITY);
    TEST_DOUBLE("%lE", "-inf", doubleval, -INFINITY);
    TEST_DOUBLE("%lE", "-infinity", doubleval, -INFINITY);
    TEST_DOUBLE("%lE", "-INF", doubleval, -INFINITY);
    TEST_DOUBLE("%lE", "-INFINITY", doubleval, -INFINITY);

    TEST_DOUBLE("%lE", "nan", doubleval, NAN);
    TEST_DOUBLE("%lE", "NAN", doubleval, NAN);
    TEST_DOUBLE("%lE", "-nan", doubleval, -NAN);
    TEST_DOUBLE("%lE", "-NAN", doubleval, -NAN);
    
    TEST_FLOAT("%a", "42", floatval, 42.0);
    TEST_FLOAT("%a", "+42", floatval, 42.0);
    TEST_FLOAT("%a", "42.0", floatval, 42.0);
    TEST_FLOAT("%a", "+42.0", floatval, 42.0);
    TEST_FLOAT("%a", "4.2e1", floatval, 42.0);
    TEST_FLOAT("%a", "+4.2e1", floatval, 42.0);
    TEST_FLOAT("%a", "4.2e+1", floatval, 42.0);
    TEST_FLOAT("%a", "+4.2e+1", floatval, 42.0);
    TEST_FLOAT("%a", "4.2E1", floatval, 42.0);
    TEST_FLOAT("%a", "+4.2E1", floatval, 42.0);
    TEST_FLOAT("%a", "4.2E+1", floatval, 42.0);
    TEST_FLOAT("%a", "+4.2E+1", floatval, 42.0);
    
    TEST_FLOAT("%a", "-42", floatval, -42.0);
    TEST_FLOAT("%a", "-42.0", floatval, -42.0);
    TEST_FLOAT("%a", "-4.2e1", floatval, -42.0);
    TEST_FLOAT("%a", "-4.2e+1", floatval, -42.0);
    TEST_FLOAT("%a", "-4.2E1", floatval, -42.0);
    TEST_FLOAT("%a", "-4.2E+1", floatval, -42.0);

    TEST_FLOAT("%a", "inf", floatval, INFINITY);
    TEST_FLOAT("%a", "infinity", floatval, INFINITY);
    TEST_FLOAT("%a", "INF", floatval, INFINITY);
    TEST_FLOAT("%a", "INFINITY", floatval, INFINITY);
    TEST_FLOAT("%a", "-inf", floatval, -INFINITY);
    TEST_FLOAT("%a", "-infinity", floatval, -INFINITY);
    TEST_FLOAT("%a", "-INF", floatval, -INFINITY);
    TEST_FLOAT("%a", "-INFINITY", floatval, -INFINITY);

    TEST_FLOAT("%a", "nan", floatval, NAN);
    TEST_FLOAT("%a", "NAN", floatval, NAN);
    TEST_FLOAT("%a", "-nan", floatval, -NAN);
    TEST_FLOAT("%a", "-NAN", floatval, -NAN);
    
    TEST_DOUBLE("%la", "42", doubleval, 42.0);
    TEST_DOUBLE("%la", "+42", doubleval, 42.0);
    TEST_DOUBLE("%la", "42.0", doubleval, 42.0);
    TEST_DOUBLE("%la", "+42.0", doubleval, 42.0);
    TEST_DOUBLE("%la", "4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%la", "+4.2e1", doubleval, 42.0);
    TEST_DOUBLE("%la", "4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%la", "+4.2e+1", doubleval, 42.0);
    TEST_DOUBLE("%la", "4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%la", "+4.2E1", doubleval, 42.0);
    TEST_DOUBLE("%la", "4.2E+1", doubleval, 42.0);
    TEST_DOUBLE("%la", "+4.2E+1", doubleval, 42.0);
    
    TEST_DOUBLE("%la", "-42", doubleval, -42.0);
    TEST_DOUBLE("%la", "-42.0", doubleval, -42.0);
    TEST_DOUBLE("%la", "-4.2e1", doubleval, -42.0);
    TEST_DOUBLE("%la", "-4.2e+1", doubleval, -42.0);
    TEST_DOUBLE("%la", "-4.2E1", doubleval, -42.0);
    TEST_DOUBLE("%la", "-4.2E+1", doubleval, -42.0);
    
    TEST_DOUBLE("%la", ".42", doubleval, 0.42);
    TEST_DOUBLE("%la", "+.42", doubleval, 0.42);
    TEST_DOUBLE("%la", "0.42", doubleval, 0.42);
    TEST_DOUBLE("%la", "+0.42", doubleval, 0.42);
    TEST_DOUBLE("%la", "4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%la", "+4.2e-1", doubleval, 0.42);
    TEST_DOUBLE("%la", "4.2E-1", doubleval, 0.42);
    TEST_DOUBLE("%la", "+4.2E-1", doubleval, 0.42);
    
    TEST_DOUBLE("%la", "inf", doubleval, INFINITY);
    TEST_DOUBLE("%la", "infinity", doubleval, INFINITY);
    TEST_DOUBLE("%la", "INF", doubleval, INFINITY);
    TEST_DOUBLE("%la", "INFINITY", doubleval, INFINITY);
    TEST_DOUBLE("%la", "-inf", doubleval, -INFINITY);
    TEST_DOUBLE("%la", "-infinity", doubleval, -INFINITY);
    TEST_DOUBLE("%la", "-INF", doubleval, -INFINITY);
    TEST_DOUBLE("%la", "-INFINITY", doubleval, -INFINITY);

    TEST_DOUBLE("%la", "nan", doubleval, NAN);
    TEST_DOUBLE("%la", "NAN", doubleval, NAN);
    TEST_DOUBLE("%la", "-nan", doubleval, -NAN);
    TEST_DOUBLE("%la", "-NAN", doubleval, -NAN);
    
    TEST_FLOAT("%f", "4e", floatval, 4.0);

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
        puts("FAILURE!");
        exit(1);
    }
    puts("SUCCESS!");
    return *quit;
}            
