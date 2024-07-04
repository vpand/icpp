#include "module.h"
#include <format>
#include <iostream>

int main(int argc, const char *argv[]) {
  HelloICPP hello;
  std::cout << std::format("Auther: {}, Version: {}.\n", hello.getAuthor(),
                           hello.version);
  return 0;
}
