#include <stddef.h>
int my_atoi(const char *arg) {
    int sign = 1;
    int res = 0;

    if(arg == NULL) {
        return 0;
    }

    if(*arg == '-') {
        sign = -1;
        arg++;
    }
    while(*arg >= '0' && *arg <= '9') {
        res *= 10;
        res += (int)((*arg) - '0');
        arg++;
    }
    return res * sign;
}
