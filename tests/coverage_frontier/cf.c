
#include <stdio.h>
#include <stdlib.h>

int foo(int x) {
  if ((x%2) == 0)
    return 0x24;
  return 0x42;
}  
      

int main(int argc, char **argv) {
  int x = atoi(argv[1]);
  printf("foo(%d) = %d\n", x, foo(x));
}
