#include <stdlib.h>

int compare(const void* a, const void* b) {
    return *(int*)a - *(int*)b;
}

int main() {
    char *good = (char *)(size_t)0xdead0;

    const int arr[10]    = {3, 2, 7, -100, 20, 2, 1, 30000, 400, -20};
    const int answer[10] = {-100, -20, 1, 2, 2, 3, 7, 20, 400, 30000};
    qsort((void*)arr, 10, 4, compare);

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
