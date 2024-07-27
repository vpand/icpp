/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "compile.h"
#include "arch.h"
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

static std::string argv_string(int argc, const char **argv) {
  std::string cmds;
  for (int i = 0; i < argc; i++)
    cmds += std::string(argv[i]) + " ";
  return cmds;
}

int compile_source_clang(int argc, const char **argv, bool cl) {
  // just echo the compiling args
  if (echocc) {
    echocc = false;
    log_print(Develop, "{}", argv_string(argc, argv));
    return 0;
  }
  if (!cl) {
    for (int i = 0; i < argc; i++) {
      if (std::string_view(argv[i]).starts_with("/clang")) {
        cl = true;
        break;
      }
    }
  }

  // construct a full path which the last element must be "clang" to make clang
  // driver happy, otherwise it can't compile source to object, it seems that
  // clang driver depends on clang name to do the right compilation logic
  auto exepath = GetExecutablePath(argv[0], true);
  // this full path ends with "clang", it's exactly the format that clang driver
  // wants
  auto program = (fs::path(exepath).parent_path() / ".." / "lib" /
                  (cl ? "clang-cl" : "clang"))
                     .string();
  auto argv0 = argv[0];
  argv[0] = program.c_str();
  // iclang_main will invoke clang_main to generate the object file with the
  // default host triple
  auto result = iclang_main(argc, argv);
  if (result) {
    argv[0] = argv0;
    log_print(Runtime, "Failed to compile: {}", argv_string(argc, argv));
  }
  return result;
}

int compile_source_icpp(int argc, const char **argv) {
  auto root = fs::absolute(fs::path(argv[0])).parent_path() / "..";
  auto rtinc = (root / "include").string();
  bool cross_compile = false, cl = false;
  std::string cppminc;
  std::vector<const char *> args;
  for (int i = 0; i < argc; i++) {
    args.push_back(argv[i]);
  }

  // make clang driver to use our fake clang path as the executable path
  args.push_back("-no-canonical-prefixes");

  // disable some warnings
  args.push_back("-Wno-deprecated-declarations");
  args.push_back("-Wno-ignored-attributes");
  args.push_back("-Wno-#pragma-messages");
  args.push_back("-Wno-unknown-argument");

  // use C++23 standard
  args.push_back("-std=c++23");
  // force to use the icpp integrated C/C++ runtime header
  args.push_back("-nostdinc++");
  args.push_back("-nostdlib++");

  /*
  The header search paths should contain the C++ Standard Library headers before
  any C Standard Library.
  */
  // add libc++ include
  auto cxxinc = std::format("-I{}/c++/v1", rtinc);
  args.push_back(cxxinc.data());

#if __APPLE__
  std::string_view argsysroot = "-isysroot";
  auto isysroot = std::format("{}/apple", rtinc);
  bool ios = false;
  for (int i = 0; i < argc - 1; i++) {
    if (std::string_view(argv[i]) == "-target") {
      auto target = std::string_view(argv[i + 1]);
      if (target.find("win") != std::string_view::npos ||
          target.find("linux") != std::string_view::npos ||
          target.find("ios") != std::string_view::npos) {
        cross_compile = true;
        ios = target.find("ios") != std::string_view::npos;
      }
      break;
    }
  }
  if (!cross_compile) {
    args.push_back(argsysroot.data());
    args.push_back(isysroot.data());
    cppminc = std::format("-fprebuilt-module-path={}/apple/module", rtinc);
    args.push_back("-target");
    args.push_back(
#if ARCH_ARM64
        "arm64"
#else
        "x86_64"
#endif
        "-apple-darwin19.0.0");
  } else if (ios) {
    args.push_back(argsysroot.data());
    args.push_back(isysroot.data());
  }
#elif ON_WINDOWS
  auto ucrtinc = std::format("-I{}/win/ucrt", rtinc);
  auto vcinc = std::format("-I{}/win/vc", rtinc);
  std::string sysroot;
  for (int i = 0; i < argc - 1; i++) {
    if (std::string_view(argv[i]) == "-target") {
      auto target = std::string_view(argv[i + 1]);
      if (target.find("apple") != std::string_view::npos ||
          target.find("linux") != std::string_view::npos) {
        ucrtinc = "";
        cross_compile = true;
      }
      break;
    }
  }
  if (ucrtinc.size()) {
    // use C++23 standard
    args.push_back("/clang:-std=c++23");
    // force to use the icpp integrated C/C++ runtime header
    args.push_back("/clang:-nostdinc++");
    args.push_back("/clang:-nostdlib++");
    args.push_back(vcinc.data());
    args.push_back(ucrtinc.data());
    args.push_back("-target");
    args.push_back(
#if ARCH_ARM64
        "aarch64"
#else
        "x86_64"
#endif
        "-pc-windows-msvc19.0.0");
    cppminc = std::format("/clang:-fprebuilt-module-path={}/win/module", rtinc);

    // MultiThreadedDLL
    args.push_back("/MD");
    // enable exception
    args.push_back("/EHsc");

    cl = true; // set as clang-cl mode
  }
#else
  for (int i = 0; i < argc - 1; i++) {
    if (std::string_view(argv[i]) == "-target") {
      auto target = std::string_view(argv[i + 1]);
      if (target.find("apple") != std::string_view::npos ||
          target.find("win") != std::string_view::npos ||
          target.find("android") != std::string_view::npos) {
        cross_compile = true;
      }
      break;
    }
  }
  if (!cross_compile) {
    args.push_back("-target");
    args.push_back(
#if ARCH_ARM64
        "aarch64"
#else
        "x86_64"
#endif
        "-unknown-linux-gnu");
  }
#endif
  if (!cppminc.size()) {
    // set for linux/android
    cppminc = std::format("-fprebuilt-module-path={}/linux/module", rtinc);
  }
  // add c++ standard module precompiled module path
  args.push_back(cppminc.data());

  // add libc include for cross compiling
  auto cinc = std::format("-I{}/c", rtinc);
  if (cross_compile) {
    bool sysroot = false;
    for (int i = 0; i < argc; i++) {
      if (std::string_view(argv[i]).find("sysroot") != std::string_view::npos) {
        sysroot = true;
        break;
      }
    }
    if (!sysroot)
      args.push_back(cinc.data());
    args.push_back("-D__ICPP_CROSS__=1");
  }

  // add include itself, the boost library needs this
  auto inc = std::format("-I{}", rtinc);
  args.push_back(inc.data());

  // add icpp module include
  auto icppinc = std::format("-I{}", RuntimeLib::inst().includeFull().string());
  args.push_back(icppinc.data());

  return compile_source_clang(static_cast<int>(args.size()), &args[0], cl);
}

fs::path compile_source_icpp(const char *argv0, std::string_view path,
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

  compile_source_icpp(static_cast<int>(args.size()), &args[0]);
  return cache.has_filename() ? cache : fs::path(opath);
}

} // namespace icpp
