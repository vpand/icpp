// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

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
