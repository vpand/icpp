/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char *argv[]) {
  char cmd[4096];
  char *ptr = cmd;
  ptr += sprintf(ptr, "%s.exe", argv[0]);
  for (int i = 1; i < argc; i++) {
    switch (*(unsigned short *)argv[i]) {
    case 'I-':
    case 'D-':
      // ignore unsupported clang compiler flags for armasm64: -Dxxx -Ixxx
      break;
    default:
      ptr += sprintf(ptr, " %s", argv[i]);
      break;
    }
  }
  printf("New assembler command: %s\n", cmd);
  return system(cmd);
}
