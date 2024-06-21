/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "compile.h"
#include "utils.h"
#include <vector>

// icpp/clang driver entry, it acts as a clang compiler when argv contains -c/-o
extern "C" int main(int argc, const char **argv);

// implement in llvm-project/clang/tools/driver/driver.cpp
extern std::string GetExecutablePath(const char *argv0, bool CanonicalPrefixes);

namespace icpp {

fs::path compile_source(const char *argv0, std::string_view path,
                        const char *opt,
                        const std::vector<const char *> &incdirs) {
  // construct a temporary output object file path
  auto opath = fs::temp_directory_path() / icpp::rand_filename(8, ".o");
  log_print(Develop, "Object path: {}", opath.c_str());

  // construct a full path which the last element must be "clang" to make clang
  // driver happy, otherwise it can't compile source to object, it seems that
  // clang driver depends on clang name to do the right compilation logic
  auto exepath = GetExecutablePath(argv0, true);
  // this full path ends with "clang", it's exactly the format that clang driver
  // wants
  auto program = fs::path(exepath).parent_path() / ".." / "lib" / "clang";

  std::vector<const char *> args;
  args.push_back(program.c_str());
  // make clang driver to use our fake clang path as the executable path
  args.push_back("-no-canonical-prefixes");
  args.push_back("-std=gnu++23");
  args.push_back(opt);
  args.push_back("-c");
  args.push_back(path.data());
  args.push_back("-o");
  args.push_back(opath.c_str());

  // add user specified include directories
  for (auto i : incdirs) {
    args.push_back(i);
  }

#if __APPLE__
#define MACOSX_SDK                                                             \
  "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/"      \
  "Developer/SDKs/MacOSX.sdk"
  args.push_back("-isysroot");
  args.push_back(MACOSX_SDK);
#elif __linux__
#error Un-implement the Linux platform currently.
#elif _WIN32
#error Un-implement the Windows platform currently.
#else
#error Unknown compiling platform.
#endif

  // main will invoke clang_main to generate the object file with the default
  // host triple
  main(static_cast<int>(args.size()), &args[0]);
  return opath;
}

} // namespace icpp
