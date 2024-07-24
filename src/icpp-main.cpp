/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "compile.h"
#include "exec.h"
#include "icpp.h"
#include "loader.h"
#include "object.h"
#include "platform.h"
#include "runcfg.h"
#include "runtime.h"
#include "llvm/Support/InitLLVM.h"
#include <format>
#include <span>

static void print_version() {
  std::cout << "ICPP " << icpp::version_string()
            << " based on Unicorn and Clang/LLVM." << std::endl
            << "Interpreting C++, running C++ in anywhere like a script."
            << std::endl
            << "Project website: https://github.com/vpand/icpp/" << std::endl
            << "Sponsor website: https://vpand.com/" << std::endl
            << std::endl;
}

static void print_help() {
  std::cout
      << "OVERVIEW: ICPP " << icpp::version_string()
      << " based on Unicorn and Clang/LLVM." << std::endl
      << "  Interpreting C++, running C++ in anywhere like a script."
      << std::endl
      << std::endl
      << "USAGE: icpp [options] exec0 [exec1 ...] [[--] args]" << std::endl
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
         "interpreter."
      << std::endl
      << "  -lname: full name of the dependent library file passed to icpp "
         "interpreter, e.g.: liba.dylib, liba.so, a.dll."
      << std::endl
      << "  -F/path/to/framework: framework search directory passed to icpp "
         "interpreter."
      << std::endl
      << "  -fname: framework name of the dependent library file passed to "
         "icpp "
         "interpreter."
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
      << "Run a C++ source file, e.g.:" << std::endl
      << "  icpp helloworld.cc" << std::endl
      << R"x(  icpp helloworld.cc -- Hello World (i.e.: argc=3, argv[]={"helloworld.cc", "Hello", "World"}))x"
      << std::endl
      << "  icpp -O3 helloworld.cc" << std::endl
      << "  icpp -O0 -p/path/to/profile.json helloworld.cc" << std::endl
      << "  icpp -I/qt/include -L/qt/lib -llibQtCore.so hellowrold.cc"
      << std::endl
      << "  icpp -I/qt/include -L/qt/lib -lQtCore.dll hellowrold.cc"
      << std::endl
      << "  icpp -I/qt/include -F/qt/framework -fQtCore hellowrold.cc"
      << std::endl
      << std::endl
      << "Run an executable, e.g.:" << std::endl
      << "  icpp -p/path/to/trace.json helloworld.exe" << std::endl
      << "  icpp -p/path/to/profile.json helloworld" << std::endl
      << std::endl
      << "Run an installed module, e.g.:" << std::endl
      << "  icpp helloworld" << std::endl
      << "  icpp helloworld -- hello world" << std::endl
      << std::endl
      << "Run the repl shell, e.g:" << std::endl
      << "  icpp" << std::endl
      << "    ICPP v0.0.1.255. Copyright (c) vpand.com.\n"
         "    Run a C++ in anywhere like a script.\n"
         "    >>> #include <stdio.h>\n"
         "    >>> puts(\"Hello world.\")\n"
      << std::endl
      << "Run an C++ expression, e.g:" << std::endl
      << R"x(  icpp "puts(std::format(\"{:x}\", 88888888).data())")x"
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
        deps.push_back(lib.string());
        break;
      }
    }
  }
  for (auto f : framedirs) {
    for (auto n : frameworks) {
      auto frame = fs::path(f) / std::format("{}.framework", n) / n;
      if (fs::exists(frame)) {
        deps.push_back(frame.string());
        break;
      }
    }
  }
  return deps;
}

extern "C" __ICPP_EXPORT__ int icpp_main(int argc, char **argv) {
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

  // if nothing input, then enter in REPL mode
  if (argc == 1)
    return icpp::exec_repl(argv[0]);

  // calculate the double dash index, all the args after idoubledash will be
  // passed to the input file as its cli argc/argv
  int idoubledash = argc, ilastfile = -1;
  for (int i = 1; i < argc; i++) {
    std::string_view arg{argv[i]};
    if (arg == "--") {
      idoubledash = i;
      break;
    }
    if (arg[0] == '-')
      continue;
    if (!fs::exists(fs::path(arg))) {
      if (ilastfile > 0)
        break;

      auto omain = icpp::RuntimeLib::inst().libFull(arg) / "main.o";
      if (fs::exists(omain))
        ilastfile = i;
    } else if (icpp::is_interpretable(arg)) {
      ilastfile = i;
    } else {
      if (ilastfile > 0)
        break;
    }
  }
  // set the implicit idoubledash position
  bool implicity = false;
  if (idoubledash == argc && ilastfile > 0) {
    idoubledash = ilastfile;
    implicity = true;
  }

  // skip argv[0] and argv[idoubledash, ...]
  auto args = std::span{
      argv + 1, static_cast<std::size_t>(idoubledash - (implicity ? 0 : 1))};

  // parse the command line arguments for icpp options
  for (auto p : args) {
    auto sp = std::string_view(p);
    if (sp == "-v" || sp == "-version") {
      print_version();
      return 0; // return to main to exit this program
    }
    if (sp == "--version") {
      print_version();
      // continuing let clang print its version
      return icpp::compile_source_clang(argc, const_cast<const char **>(argv));
    }
    if (sp == "-h" || sp == "-help") {
      print_help();
      return 0;
    }
    if (sp == "--help") {
      print_help();
      // continuing let clang print its help list
      return icpp::compile_source_clang(argc, const_cast<const char **>(argv));
    }
    if (sp == "-c" || sp == "-o") {
      icpp::RunConfig::inst(argv[0], "");
      // let clang do the compilation task directly
      return icpp::compile_source_clang(argc, const_cast<const char **>(argv));
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
  icpp::RunConfig::inst(argv[0], icpp_option_procfg);

  auto deps = get_dependencies(icpp_option_libdirs, icpp_option_libs,
                               icpp_option_framedirs, icpp_option_frameworks);
  // interpret the input Source-C++ or
  // Executable-MachO/Executable-ELF/Executable-PE files
  int exitcode = 0;
  bool validcache = true;
  for (auto p : args) {
    auto sp = std::string_view(p);
    if (sp[0] == '-')
      continue;
    if (!fs::exists(fs::path(sp))) {
      // execute as an installed module
      auto omain = icpp::RuntimeLib::inst().libFull(sp) / "main.o";
      if (fs::exists(omain)) {
        exitcode = icpp::exec_main(omain.string(), deps, sp, argc - idoubledash,
                                   &argv[idoubledash + 1], validcache);
      } else {
        // execute as a dynamic code snippet
        icpp::RunConfig::repl = true;
        exitcode = icpp::exec_string(argv[0], std::string(sp));
        if (exitcode)
          icpp::log_print(
              icpp::Raw,
              "Tried to run as an C++ expression but failed, make sure that "
              "your input file exists or the expression is valid.");
      }
      continue;
    }
    if (icpp::is_cpp_source(sp)) {
      while (true) {
        // compile the input source to be as the running host object file(.o,
        // .obj)
        auto opath = icpp::compile_source_icpp(argv[0], sp, icpp_option_opt,
                                               icpp_option_incdirs);
        if (fs::exists(opath)) {
          exitcode =
              icpp::exec_main(opath.string(), deps, sp, argc - idoubledash,
                              &argv[idoubledash + 1], validcache);
          if (opath.extension() != icpp::iobj_ext) {
            // remove the temporary intermediate object file
            fs::remove(opath);
            // done
            break;
          } else if (validcache) {
            // done
            break;
          } else {
            // remove the version miss-matched iobject cache file
            fs::remove(opath);
            icpp::log_print(icpp::Develop,
                            "Removed the old iobject cache file: {}.",
                            opath.string());
          }
        } else {
          // if failed to compile the input source, clang has already printed
          // the errors
          break;
        }
      }
    } else {
      // pass sp as an executable file
      exitcode = icpp::exec_main(sp, deps, sp, argc - idoubledash,
                                 &argv[idoubledash + 1], validcache);
    }
  }
  icpp::Loader::deinitialize(exitcode);
  return exitcode;
}
