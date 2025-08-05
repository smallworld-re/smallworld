// A small program that should be a little challenging but possible to
// auto-harness with magrathea

#include <stdio.h>
#include <string.h>

// this is the fn we'll try to autoharness
int foo(char *buf, unsigned int len) {
  // mag needs to figure out that this function's 1st arg is a ptr to memory
  // that is an input to the fn and that len is the length of that buffer.

  int x=0;
  // mag needs to figure out that len is compared against a literal
  // and thus has two values of interest: 12 and anything else.
  if (len == 12) {
    for (int i=0; i<len; i++) {
      if ((buf[i]%3) == 0)
	x *= 3;
      else
	x -= x/2;
      if (buf[i] == 42)
	x = 42;      
    }
  }
  else {
    for (int i=0; i<len; i++) 
      x += buf[i] % 42;
  }
  return x;
}


int main(int argc, char **argv) {
  int x = foo(argv[1], strlen(argv[1]));
  printf("x=%d\n", x);
}

   
  
