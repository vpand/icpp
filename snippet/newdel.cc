#include <stdio.h>

int main(int argc, const char *argv[]) {
  int *iptr = new int;
  char *cptr = new char[16];
  printf("iptr=%p, cptr=%p.\n", iptr, cptr);
  delete iptr;
  delete[] cptr;
  return 0;
}
