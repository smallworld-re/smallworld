#include <stdio.h>
#include <stdlib.h>
#include <math.h>

struct res {
    int x;
    int j;
};

struct res coll(int x) {
    int j = 0;
    while (1) {
        if ((x % 2) == 0) 
            x /= 2;
        else
            x = 3 * x + 1;
        j += 1;
        /* if ((j % 100000) == 0)  */
        /*     printf("%d iterations\n", j); */
        int a = (x+1) * (x+2) * (x+3); 
        if (a == 24)
            break;
    }
    struct res r;
    r.x = x;
    r.j = j;
    return r;
}


int main(int argc, char **argv) {
    int a;
    struct res r; 

    a = atoi(argv[1]);
    r = coll(a);

    if (r.x==1) 
        printf("expected (%d)\n", r.j);
    else
        printf("unexpected (%d)\n", r.j);

       
}
