#include <stdio.h>

int main(int argc, const char *argv[]) {
  printf("argc=%d, argv={", argc);
  for (int i = 0; i < argc; i++) {
    printf("\"%s\", ", argv[i]);
  }
  puts("}");
  return 0;
}
