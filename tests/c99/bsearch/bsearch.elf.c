#include <stdlib.h>
#define ARR_LEN 10

int compare(const void* a, const void* b) {
    return *(int*)a - *(int*)b;
}

int main(int argc, char *argv[]) {
    char *good = (char *)(size_t)0xdead;
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

    return *good;
}
