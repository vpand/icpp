/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#if _WIN64

extern "C" __declspec(dllimport) int icpp_gadget(int argc, char **argv);
int main(int argc, char **argv) { return icpp_gadget(argc, argv); }

#else

#include <boost/dll.hpp>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>

#include <llvm/Config/config.h>
#include <llvm/Config/llvm-config.h>

using namespace boost;
namespace fs = std::filesystem;

int main(int argc, const char **argv) {
  try {
    // set icpp-server mode flag
    setenv("icpp-server", "1", true);

    // i.e.: icpp-gadget.dylib, icpp-gadget.so, icpp-gadget.dll
    auto icpp = std::format("icpp-gadget{}", LLVM_PLUGIN_EXT);
    // cli and lib must be in the same directory
    auto libicpp = fs::path(argv[0]).parent_path() / icpp;

    auto icpp_gadget = dll::import_symbol<int(int, const char **)>(
        libicpp.string(), "icpp_gadget");
    // call the real icpp main entry
    return icpp_gadget(argc, argv);
  } catch (system::system_error &e) {
    std::cout << "Fatal error when loading icpp: " << e.what() << std::endl;
  } catch (...) {
    std::cout << "Fatal error when loading icpp." << std::endl;
  }
  return -1;
}

#endif
