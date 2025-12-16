#include <stdlib.h>

int compare(const void* a, const void* b) {
    return *(int*)a - *(int*)b;
}

int main(int argc, char *argv[]) {
    char *good = (char *)(size_t)0xdead;

    const int arr[10]    = {3, 2, 7, -100, 20, 2, 1, 30000, 400, -20};
    const int answer[10] = {-100, -20, 1, 2, 2, 3, 7, 20, 400, 30000};
    qsort((void*)arr, 10, 4, compare);

    for (int i = 0; i < 10; i++) {
        if (arr[i] != answer[i]) {
            return 1;
        }
    }

    return *good;
}
