/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "icpp.h"
#include <iostream>
#include <span>
#include <string_view>

using namespace std::literals;

static void print_version() {
  std::cout
      << "ICPP " << icpp::version_string()
      << " based on Unicorn and Clang/LLVM." << std::endl
      << "Interpreting C++, executing the source and executable like a script."
      << std::endl
      << "Project website: https://github.com/vpand/icpp/" << std::endl
      << "Sponsor website: https://vpand.com/" << std::endl
      << std::endl;
}

int icpp_main(int argc, char **argv) {
  auto args = std::span{argv, static_cast<std::size_t>(argc)};
  for (auto p : args) {
    auto sp = std::string_view(p);
    if (sp == "-v"sv || sp == "-version"sv) {
      print_version();
      std::exit(0);
    }
    if (sp == "--version"sv) {
      print_version();
      return 1; // continuing let clang print its version
    }
  }
  return -1;
}
