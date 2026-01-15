#include <stddef.h>
long strtol(const char *arg, char **endptr, int base) {
    int sign = 1;
    long res = 0;

    // NOTE: This is not a complete implementation.
    // The real one will handle endptr and base.

    if(arg == NULL) {
        return 0;
    }

    if(*arg == '-') {
        sign = -1l;
        arg++;
    }    

    while(*arg >= '0' && *arg <= '9') {
        res *= 10;
        res += (long)((*arg) - '0');
        arg++;
    }
    return res * sign;
}

int atoi(const char *arg) {
    return (int)strtol(arg, NULL, 10);
}
