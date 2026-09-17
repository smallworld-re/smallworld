#include <stdlib.h>
#define ARR_LEN 10

int compare(const void* a, const void* b) {
    return *(int*)a - *(int*)b;
}

int main() {
    char *good = (char *)(size_t)0xdead0;
    const int arr[ARR_LEN] = {-100, -20, 1, 2, 2, 3, 7, 20, 400, 30000};

    // success cases
    int key = 7;
    const void* answer = bsearch((const void*)&key, (const void*)arr, ARR_LEN, sizeof(int), compare);
    if (answer != &arr[6]) {
        return 1;
    }
    key = 400;
    answer = bsearch((const void*)&key, (const void*)arr, ARR_LEN, sizeof(int), compare);
    if (answer != &arr[8]) {
        return 1;
    }
    key = -20;
    answer = bsearch((const void*)&key, (const void*)arr, ARR_LEN, sizeof(int), compare);
    if (answer != &arr[1]) {
        return 1;
    }

    // test key not in array
    key = 5;
    answer = bsearch((const void*)&key, (const void*)arr, ARR_LEN, sizeof(int), compare);
    if (answer != NULL) {
        return 1;
    }

    // Empty array: C returns NULL without ever calling the comparator. The
    // previous model instead computed mid == -1 and compared base[-1]. We
    // search an empty range that starts at sentinel[1], so base[-1] is the
    // mapped sentinel[0] == 7. The buggy model's compare(key, base[-1])
    // returns 0 and it hands back &sentinel[0] (non-NULL); the fixed model
    // returns NULL without a comparison. No comparator-call counter is used
    // because a global would be addressed GP-relative on MIPS, which the
    // test harness does not set up.
    const int sentinel[2] = {7, 999};
    key = 7;
    answer = bsearch((const void*)&key, (const void*)&sentinel[1], 0, sizeof(int), compare);
    if (answer != NULL) {
        return 1;
    }

    return *good;
}
