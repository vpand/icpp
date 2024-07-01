/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "compile.h"
#include "object.h"
#include "runcfg.h"
#include "utils.h"
#include <vector>

// clang compiler main entry
int iclang_main(int argc, const char **argv);

// implement in llvm-project/clang/tools/driver/driver.cpp
extern std::string GetExecutablePath(const char *argv0, bool CanonicalPrefixes);

namespace icpp {

static fs::path check_cache(std::string_view path) {
  auto srcpath = fs::path(path);
  auto cachepath = fs::absolute(srcpath.parent_path()) /
                   (srcpath.stem().string() + iobj_ext.data());
  if (!fs::exists(cachepath)) {
    return "";
  }
  auto srctm = fs::last_write_time(srcpath);
  auto objtm = fs::last_write_time(cachepath);
  if (srctm > objtm) {
    // source has been updated, so the cache file becomes invalid
    return "";
  }
  log_print(Runtime, "Using iobject cache file: {}.", cachepath.string());
  return cachepath;
}

static int compile_source_clang(int argc, const char **argv) {
  // construct a full path which the last element must be "clang" to make clang
  // driver happy, otherwise it can't compile source to object, it seems that
  // clang driver depends on clang name to do the right compilation logic
  auto exepath = GetExecutablePath(argv[0], true);
  // this full path ends with "clang", it's exactly the format that clang driver
  // wants
  auto program = fs::path(exepath).parent_path() / ".." / "lib" / "clang";
  argv[0] = program.c_str();
  // iclang_main will invoke clang_main to generate the object file with the
  // default host triple
  return iclang_main(argc, argv);
}

int compile_source(int argc, const char **argv) {
  std::vector<const char *> args;
  for (int i = 0; i < argc; i++)
    args.push_back(argv[i]);

  // make clang driver to use our fake clang path as the executable path
  args.push_back("-no-canonical-prefixes");
  // use C++23 standard
  args.push_back("-std=gnu++23");

  // add some system level specific compiler flags
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

  return compile_source_clang(static_cast<int>(args.size()), &args[0]);
}

fs::path compile_source(const char *argv0, std::string_view path,
                        const char *opt,
                        const std::vector<const char *> &incdirs) {
  // directly return the cache file if there exists one
  auto cache = check_cache(path);
  if (cache.has_filename()) {
    return cache;
  }
  // construct a temporary output object file path
  auto opath = fs::temp_directory_path() / icpp::rand_filename(8, ".o");
  log_print(Develop, "Object path: {}", opath.c_str());

  std::vector<const char *> args;
  args.push_back(argv0);
  // used to indicate the source location when script crashes
  if (opt[2] == '0') {
    // only generate dwarf debug information for non-optimization compilation
    args.push_back("-g");
  }
  // suppress all warnings if in repl mode
  if (RunConfig::repl) {
    args.push_back("-w");
  }
  args.push_back(opt);
  args.push_back("-c");
  args.push_back(path.data());
  args.push_back("-o");
  args.push_back(opath.c_str());

  // add user specified include directories
  for (auto i : incdirs) {
    args.push_back(i);
  }
  compile_source(static_cast<int>(args.size()), &args[0]);
  return opath;
}

} // namespace icpp
