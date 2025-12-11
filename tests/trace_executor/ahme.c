// A small program that should be a little challenging but possible to
// auto-harness with magrathea

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// this is the fn we'll try to autoharness
int foo(char *buf, unsigned int len, int y) {
  // mag needs to figure out that this function's 1st arg is a ptr to memory
  // that is an input to the fn and that len is the length of that buffer.

  int x=0;
  // Magrathea needs to figure out that len is compared against a literal
  // and thus has two values of interest: 47 and anything else.  
  // Note that colors < 0x20 are ignored, sadly.  So the hope is we
  // get 47 and not-47 and not-47 is very likely a very large number
  if (len == 47) {
    // if y is uninitialized, it will be 0
    // so this branch can distinguish between randomizing regs and not
    if (y != 0)
      len /= 2;
    for (int i=0; i<len; i++) {
      if ((buf[i]%3) == 0)
	x *= 3;
      else
	x -= x/2;
      if (buf[i] == 42)
	x = 0;      
    }
  }
  else {
    for (int i=0; i<len; i++) 
      x += buf[i] % 17;
  }
  return x;
}


int main(int argc, char **argv) {
  int x = foo(argv[1], strlen(argv[1]), atoi(argv[2]));
  printf("x=%d\n", x);
}

   
  
