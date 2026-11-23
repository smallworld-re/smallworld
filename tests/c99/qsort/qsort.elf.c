#include <stdlib.h>

#ifdef __SDCC
// SDCC's library calls the comparator with its reentrant convention, and
// does not warn when given one compiled with its default convention.
#define CALLBACK __reentrant
#else
#define CALLBACK
#endif

int compare(const void* a, const void* b) CALLBACK {
    return *(int*)a - *(int*)b;
}

int main() {
    char *good = (char *)(size_t)0xdead0;

    const int arr[10]    = {3, 2, 7, -100, 20, 2, 1, 30000, 400, -20};
    const int answer[10] = {-100, -20, 1, 2, 2, 3, 7, 20, 400, 30000};
    qsort((void*)arr, 10, sizeof(int), compare);

    for (int i = 0; i < 10; i++) {
        if (arr[i] != answer[i]) {
            return 1;
        }
    }

    // A run of 0 or 1 elements is already sorted: C performs no comparisons.
    // The previous model unconditionally compared element [1] against [0],
    // reading past a 0- or 1-element array (which the model surfaced as a
    // hard error). The fixed model returns without touching the comparator.
    int one[1] = {42};

    qsort((void*)one, 1, sizeof(int), compare);
    if (one[0] != 42) {
        return 1;
    }

    qsort((void*)one, 0, sizeof(int), compare);
    if (one[0] != 42) {
        return 1;
    }

    return *good;
}
