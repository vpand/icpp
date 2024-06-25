/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include <boost/dll.hpp>
#include <filesystem>
#include <format>
#include <iostream>

#include <llvm/Config/config.h>
#include <llvm/Config/llvm-config.h>

using namespace boost;
namespace fs = std::filesystem;

int main(int argc, const char **argv) {
  try {
    // i.e.: icpp.19.dylib, icpp.19.so, icpp.19.dll
    auto icpp = std::format("icpp.{}{}", LLVM_VERSION_MAJOR, LLVM_PLUGIN_EXT);
    // cli and lib must be in the same directory
    auto libicpp = fs::path(argv[0]).parent_path() / icpp;

    auto icpp_main = dll::import_symbol<int(int, const char **)>(
        libicpp.string(), "icpp_main");
    // call the real icpp main entry
    return icpp_main(argc, argv);
  } catch (system::system_error &e) {
    std::cout << "Fatal error when loading icpp: " << e.what() << std::endl;
  } catch (...) {
    std::cout << "Fatal error when loading icpp." << std::endl;
  }
  return -1;
}
