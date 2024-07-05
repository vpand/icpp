/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "compile.h"
#include "object.h"
#include "platform.h"
#include "runcfg.h"
#include "runtime.h"
#include "utils.h"
#include <vector>

// clang compiler main entry
int iclang_main(int argc, const char **argv);

// implement in llvm-project/clang/tools/driver/driver.cpp
extern std::string GetExecutablePath(const char *argv0, bool CanonicalPrefixes);

namespace icpp {

static bool echocc = false;

static int compile_source_clang(int argc, const char **argv) {
  // just echo the compiling args
  if (echocc) {
    std::string cmds;
    for (int i = 0; i < argc; i++)
      cmds += std::string(argv[i]) + " ";
    log_print(Develop, "{}", cmds);
    return 0;
  }

  // construct a full path which the last element must be "clang" to make clang
  // driver happy, otherwise it can't compile source to object, it seems that
  // clang driver depends on clang name to do the right compilation logic
  auto exepath = GetExecutablePath(argv[0], true);
  // this full path ends with "clang", it's exactly the format that clang driver
  // wants
  auto program =
      (fs::path(exepath).parent_path() / ".." / "lib" / "clang").string();
  argv[0] = program.c_str();
  // iclang_main will invoke clang_main to generate the object file with the
  // default host triple
  return iclang_main(argc, argv);
}

int compile_source(int argc, const char **argv) {
  std::vector<const char *> args;
  bool crossbuild = false;
  for (int i = 0; i < argc; i++) {
    args.push_back(argv[i]);
    // check whether in cross build mode
    if (!crossbuild && (std::string_view(argv[i]) == "-arch" ||
                        std::string_view(argv[i]) == "-target"))
      crossbuild = true;
  }

  // make clang driver to use our fake clang path as the executable path
  args.push_back("-no-canonical-prefixes");
  // use C++23 standard
  args.push_back("-std=gnu++23");

  // add some system level specific compiler flags for host target build
  auto eflags = extra_cflags();
  if (!crossbuild) {
    for (auto &a : eflags)
      args.push_back(a.data());
  }

  // add icpp include
  auto icppinc = std::format(
      "-I{}", (fs::absolute(fs::path(argv[0])).parent_path() / ".." / "include")
                  .string());
  args.push_back(icppinc.data());

  // add icpp module include
  auto icppminc =
      std::format("-I{}", RuntimeLib::inst().includeFull().string());
  args.push_back(icppminc.data());

  return compile_source_clang(static_cast<int>(args.size()), &args[0]);
}

fs::path compile_source(const char *argv0, std::string_view path,
                        const char *opt,
                        const std::vector<const char *> &incdirs) {
  // construct a temporary output object file path
  auto opath =
      (fs::temp_directory_path() / icpp::rand_filename(8, obj_ext)).string();
  log_print(Develop, "Object path: {}", opath);

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

  // using the cache file if there exists one
  auto cache = convert_file(path, iobj_ext);
  if (cache.has_filename()) {
    log_print(Develop, "Using iobject cache file when compiling: {}.",
              cache.string());
    // print the current compiling args
    echocc = true;
  }

  compile_source(static_cast<int>(args.size()), &args[0]);
  return cache.has_filename() ? cache : fs::path(opath);
}

} // namespace icpp
