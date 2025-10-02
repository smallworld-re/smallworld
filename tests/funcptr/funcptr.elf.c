#include "stdio.h"
#include "stdlib.h"

void callee() {
    printf("Called!\n");
}

void caller(void (*fptr)(void)) {
    fptr();
}

int comp(const void* a, const void* b) {
    return *((int*)a) - *((int*)b);
}

int main() {
    printf("Haven't called yet...\n");
    caller(&callee);
    printf("And now we return :)\n");

    const int n = 5;
    int array[] = {1, 5, 2, 4, 3};
    for (int i = 0; i < n; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");

    qsort(array, n, sizeof(array[0]), &comp);

    for (int i = 0; i < n; i++) {
        printf("%d ", array[i]);
    }
    printf("\n");
}
