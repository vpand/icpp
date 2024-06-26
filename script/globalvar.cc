#include <stdio.h>

static int sgvar1 = 1;
static int sgvar2;
int gvar1 = 2;
int gvar2;

int main(int argc, const char *argv[]) {
  printf("inited vars: %p %p\nun-inited vars: %p %p\n", &sgvar1, &gvar1,
         &sgvar2, &gvar2);
  return 0;
}
