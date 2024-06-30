/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "compile.h"
#include "exec.h"
#include "icpp.h"
#include "object.h"
#include "runcfg.h"
#include "llvm/Support/InitLLVM.h"
#include <format>
#include <span>

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

static void print_help() {
  std::cout
      << "OVERVIEW: ICPP " << icpp::version_string()
      << " based on Unicorn and Clang/LLVM." << std::endl
      << "  Interpreting C++, executing the source and executable like a "
         "script."
      << std::endl
      << std::endl
      << "USAGE: icpp [options] file0 [file1 ...] [-- args]" << std::endl
      << "OPTIONS:" << std::endl
      << "  -v, -version: print icpp version." << std::endl
      << "  --version: print icpp and clang version." << std::endl
      << "  -h, -help: print icpp help list." << std::endl
      << "  --help: print icpp and clang help list." << std::endl
      << "  -O0, -O1, -O2, -O3, -Os, -Oz: optimization level passed to "
         "clang, default to -O2."
      << std::endl
      << "  -I/path/to/include: header include directory passed to clang."
      << std::endl
      << "  -L/path/to/library: library search directory passed to icpp "
         "interpreting engine."
      << std::endl
      << "  -lname: full name of the dependent library file passed to icpp "
         "interpreting engine, e.g.: liba.dylib, liba.so, a.dll."
      << std::endl
      << "  -F/path/to/framework: framework search directory passed to icpp "
         "interpreting engine."
      << std::endl
      << "  -fname: framework name of the dependent library file passed to "
         "icpp "
         "interpreting engine."
      << std::endl
      << "  -p/path/to/json: professional json configuration file for "
         "trace/profile/plugin/etc.."
      << std::endl
      << "FILES: input file can be C++ source code(.c/.cc/.cpp/.cxx), "
         "MachO/ELF/PE executable."
      << std::endl
      << "ARGS: arguments passed to the main entry function of the input files."
      << std::endl
      << std::endl
      << "e.g.:" << std::endl
      << "  icpp helloworld.cc" << std::endl
      << R"x(  icpp helloworld.cc -- Hello World (i.e.: argc=3, argv[]={"helloworld.cc", "Hello", "World"}))x"
      << std::endl
      << "  icpp -O3 helloworld.cc" << std::endl
      << "  icpp -O0 -p/path/to/profile.json helloworld.cc" << std::endl
      << "  icpp -p/path/to/trace.json helloworld.exe" << std::endl
      << "  icpp -I/qt/include -L/qt/lib -llibQtCore.so hellowrold.cc"
      << std::endl
      << "  icpp -I/qt/include -L/qt/lib -lQtCore.dll hellowrold.cc"
      << std::endl
      << "  icpp -I/qt/include -F/qt/framework -fQtCore hellowrold.cc"
      << std::endl
      << std::endl;
}

static std::vector<std::string>
get_dependencies(const std::vector<const char *> &libdirs,
                 const std::vector<const char *> &libs,
                 const std::vector<const char *> &framedirs,
                 const std::vector<const char *> &frameworks) {
  std::vector<std::string> deps;
  for (auto l : libdirs) {
    for (auto n : libs) {
      auto lib = fs::path(l) / n;
      if (fs::exists(lib)) {
        deps.push_back(lib);
        break;
      }
    }
  }
  for (auto f : framedirs) {
    for (auto n : frameworks) {
      auto frame = fs::path(f) / std::format("{}.framework", n) / n;
      if (fs::exists(frame)) {
        deps.push_back(frame);
        break;
      }
    }
  }
  return deps;
}

extern "C" __ICPP_EXPORT__ int icpp_main(int argc, char **argv) {
  using namespace std::literals;
  llvm::InitLLVM X(argc, argv);

  // optimization level passed to clang
  const char *icpp_option_opt = "-O2";

  // include directory passed to clang
  std::vector<const char *> icpp_option_incdirs;

  // library directory passed to exec engine
  std::vector<const char *> icpp_option_libdirs;

  // library name passed to exec engine for dependent runtime symbol lookup
  std::vector<const char *> icpp_option_libs;

  // framework directory passed to exec engine
  std::vector<const char *> icpp_option_framedirs;

  // framework name passed to exec engine for dependent runtime symbol lookup
  std::vector<const char *> icpp_option_frameworks;

  // professional json configuration file for trace/profile/plugin
  const char *icpp_option_procfg = "";

  // mark the double dash index, all the args after idoubledash will be passed
  // to the input file
  int idoubledash = argc;
  for (int i = 0; i < argc; i++) {
    if (std::string_view(argv[i]) == "--"sv) {
      idoubledash = i;
      break;
    }
  }

  // skip argv[0] and argv[idoubledash, ...]
  auto args = std::span{argv + 1, static_cast<std::size_t>(idoubledash - 1)};

  // parse the command line arguments for icpp options
  for (auto p : args) {
    auto sp = std::string_view(p);
    if (sp == "-v"sv || sp == "-version"sv) {
      print_version();
      return 0; // return to main to exit this program
    }
    if (sp == "--version"sv) {
      print_version();
      return 1; // continuing let clang print its version
    }
    if (sp == "-h"sv || sp == "-help"sv) {
      print_help();
      return 0;
    }
    if (sp == "--help"sv) {
      print_help();
      return 1; // continuing let clang print its help list
    }
    if (sp == "-c"sv || sp == "-o"sv) {
      return 1; // continuing let clang do the compilation task
    }
    if (sp.starts_with("-I")) {
      // forward to clang
      icpp_option_incdirs.push_back(sp.data());
    } else if (sp.starts_with("-L")) {
      icpp_option_libdirs.push_back(sp.data() + 2);
    } else if (sp.starts_with("-l")) {
      icpp_option_libs.push_back(sp.data() + 2);
    } else if (sp.starts_with("-F")) {
      icpp_option_framedirs.push_back(sp.data() + 2);
    } else if (sp.starts_with("-f")) {
      icpp_option_frameworks.push_back(sp.data() + 2);
    } else if (sp.starts_with("-p")) {
      icpp_option_procfg = sp.data() + 2;
    }
  }

  // initialize the running configuration
  icpp::RunConfig::inst(icpp_option_procfg);

  auto deps = get_dependencies(icpp_option_libdirs, icpp_option_libs,
                               icpp_option_framedirs, icpp_option_frameworks);
  // interpret the input Source-C++ or
  // Executable-MachO/Executable-ELF/Executable-PE files
  for (auto p : args) {
    auto sp = std::string_view(p);
    if (sp[0] == '-')
      continue;
    if (!fs::exists(fs::path(sp))) {
      std::cout << "Input file '" << sp << "' doesn't exist." << std::endl;
      continue;
    }
    if (icpp::is_cpp_source(sp)) {
      // compile the input source to be as the running host object file(.o,
      // .obj)
      auto opath = icpp::compile_source(argv[0], sp, icpp_option_opt,
                                        icpp_option_incdirs);
      if (fs::exists(opath)) {
        icpp::exec_main(opath.c_str(), deps, sp, argc - idoubledash,
                        &argv[idoubledash + 1]);
        if (opath.extension() != icpp::iobj_ext)
          fs::remove(opath);
      } else {
        // if failed to compile the input source, clang has already printed the
        // errors
      }
    } else {
      // pass sp as an executable file
      icpp::exec_main(sp, deps, sp, idoubledash - argc, &argv[idoubledash + 1]);
    }
  }
  return 0;
}
