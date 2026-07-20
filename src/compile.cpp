/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

#include "compile.h"
#include "arch.h"
#include "object.h"
#include "platform.h"
#include "runcfg.h"
#include "runtime.h"
#include "utils.h"
#include <atomic>
#include <fstream>
#include <optional>
#include <vector>
#ifdef ON_WINDOWS
#include <boost/process.hpp>
#include <boost/process/windows.hpp>
#else
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <boost/process.hpp>
#pragma clang diagnostic pop
#endif

namespace proc = boost::process;

#if 0
// implement in llvm-project/clang/tools/driver/driver.cpp
extern std::string GetExecutablePath(const char *argv0, bool CanonicalPrefixes);
#else
static std::string GetExecutablePath(const char *argv0,
                                     bool CanonicalPrefixes) {
  return fs::absolute(argv0);
}
#endif

namespace icpp {

static bool echocc = false;
static std::string pcm_root;

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
    log_print(Develop, "Failed to compile: {}", argv_string(argc, argv));
  }
  return result;
}

int compile_source_icpp(int argc, const char **argv) {
  auto root = fs::absolute(fs::path(argv[0])).parent_path() / "..";
  auto rtinc = (root / "include").string();
  bool cross_compile = false, cl = false, cppsrc = true;
  std::string cppminc;
  std::vector<const char *> args;
  for (int i = 0; i < argc; i++) {
    if (std::string_view(argv[i]) == "-c" && is_c_source(argv[i + 1]))
      cppsrc = false;
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
  if (cppsrc)
    args.push_back("-std=c++23");

  /*
  The header search paths should contain the C++ Standard Library headers before
  any C Standard Library.
  */
  // add libc++ include
  auto cxxinc = std::format("-I{}/c++/v1", rtinc);
  if (cppsrc) {
    args.push_back(cxxinc.data());
    // force to use the icpp integrated C/C++ runtime header
    args.push_back("-nostdinc++");
    args.push_back("-nostdlib++");
  }

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
    if (cppsrc) {
      args.push_back("/clang:-std=c++23");
      // force to use the icpp integrated C/C++ runtime header
      args.push_back("/clang:-nostdinc++");
      args.push_back("/clang:-nostdlib++");
    }
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
    cppminc = "/clang:";

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

  // add c++ standard module precompiled module path
  if (cppsrc && !cross_compile) {
    cppminc += std::format("-fprebuilt-module-path={}", pcm_root);
    args.push_back(cppminc.data());
  }

  // add libc include for cross compiling
  auto cinc = std::format("-I{}/c", rtinc);
  if (cross_compile) {
    bool sysroot = false;
    for (auto &arg : args) {
      if (std::string_view(arg).find("sysroot") != std::string_view::npos) {
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
  std::vector<std::string> modincs;
  auto rootinc = RuntimeLib::inst().includeFull().string();
  for (auto &m : RuntimeLib::inst().modules()) {
    auto icppinc = std::format("-I{}/{}", rootinc, m);
    modincs.push_back(std::move(icppinc));
    args.push_back(modincs.rbegin()->data());
  }

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
    // echo the current compiling args in subroutines to prevent the actual
    // compilation
    echocc = true;
    compile_source_icpp(static_cast<int>(args.size()), &args[0]);
    return cache;
  } else {
    // compile the input source in a standalone icpp process
    std::vector<std::string> ccargs;
    for (auto i = 1; i < args.size(); i++)
      ccargs.push_back(args[i]);

#ifdef ON_WINDOWS
    if (::GetConsoleWindow() == nullptr) {
      // Within a GUI process, like Cutter++ in Cutter, redirect clang's
      // potential outputs to GUI
      proc::ipstream pipe_stream;
      proc::child compiler(std::string(argv0), ccargs,
                           proc::std_out > pipe_stream,
                           proc::std_err > pipe_stream, proc::windows::hide);
      compiler.wait();
      if (compiler.exit_code() != 0) {
        std::string output((std::istreambuf_iterator<char>(pipe_stream)),
                           std::istreambuf_iterator<char>());
        log_print(Runtime, "{}", output);
      }
    } else {
      // Console
      proc::child compiler(std::string(argv0), ccargs);
      compiler.wait();
    }
#else
    proc::child compiler(std::string(argv0), ccargs);
    compiler.wait();
#endif
    return fs::path(opath);
  }
}

static void precompile_module(const char *argv0, const fs::path &root,
                              const fs::path pcmroot, const fs::path &cppm) {
  must_exist(pcmroot);

  auto cppmpath = (root / "module" / cppm).string();
  auto pcmpath = (pcmroot / cppm.stem()).string() + ".pcm";

  std::vector<const char *> args;
  args.push_back(argv0);
  args.push_back("-w");
#if _WIN32
  std::string outarg("/clang:");
  outarg += pcmpath;
  args.push_back("/clang:-o");
  args.push_back(outarg.data());
  args.push_back("/clang:--precompile");
#else
  args.push_back("-o");
  args.push_back(pcmpath.data());
  args.push_back("--precompile");
#endif
  args.push_back(cppmpath.data());

  log_print(Develop, "Precompiling {} to {} ...", cppmpath, pcmpath);
  compile_source_icpp(static_cast<int>(args.size()), &args[0]);
}

void precompile_module(const char *argv0) {
  auto pcmroot =
      fs::path(home_directory()) /
      std::format(".icpp/module/{:08x}",
                  static_cast<uint32_t>(std::hash<std::string>{}(argv0)));
  pcm_root = pcmroot.string();
  if (fs::exists(pcmroot))
    return; // already generated the standard pcm files

  log_print(Raw, "Initializing the standard C++ modules...");

  auto icpproot = fs::path(argv0).parent_path().parent_path();
  for (auto &cppm : {"std.cppm", "std.compat.cppm"})
    precompile_module(argv0, icpproot, pcmroot, cppm);

  std::ofstream outf(pcmroot / "icpp.txt");
  outf << argv0 << std::endl;
}

int cformat_main(int argc, const char *argv[]) {
  std::vector<std::string> fargs;
  for (auto i = 1; i < argc; i++)
    fargs.push_back(argv[i]);
  auto format = fs::path(argv[0]).parent_path() / "clang-format"
#if ON_WINDOWS
                                                  ".exe"
#endif
      ;
  proc::child child(format.string(), fargs);
  child.wait();
  return child.exit_code();
}

} // namespace icpp
