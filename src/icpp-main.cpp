/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "exec.h"
#include "icpp.h"
#include "utils.h"
#include <filesystem>
#include <span>
#include <vector>

using namespace std::literals;
namespace fs = std::filesystem;

extern "C" int main(int argc, const char **argv);

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
      << "USAGE: icpp [options] file0 [file1]..." << std::endl
      << "OPTIONS:" << std::endl
      << "  -v, -version: print icpp version." << std::endl
      << "  --version: print icpp and clang version." << std::endl
      << "  -h: print icpp help list." << std::endl
      << "  -help, --help: print icpp and clang help list." << std::endl
      << "FILES: input file can be C++ source code, MachO/ELF/PE executable."
      << std::endl
      << std::endl;
}

// implement in llvm-project/clang/tools/driver/driver.cpp
extern std::string GetExecutablePath(const char *Argv0, bool CanonicalPrefixes);

static fs::path compile_source(const char *Argv0, std::string_view path) {
  // construct a temporary output object file path
  auto opath = fs::temp_directory_path() / icpp::rand_filename(8, ".o");

  // construct a full path which the last element must be "clang" to make clang
  // driver happy, otherwise it can't compile source to object, it seems that
  // clang driver depends on clang name to do the right compilation logic
  auto exepath = GetExecutablePath(Argv0, true);
  // this full path ends with "clang", it's exactly the format that clang driver
  // wants
  auto program = fs::path(exepath).parent_path() / ".." / "lib" / "clang";

  std::vector<const char *> args;
  args.push_back(program.c_str());
  // make clang driver to use our fake clang path as the executable path
  args.push_back("-no-canonical-prefixes");
  args.push_back("-std=gnu++23");
  args.push_back("-O2");
  args.push_back("-c");
  args.push_back(path.data());
  args.push_back("-o");
  args.push_back(opath.c_str());

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

int icpp_main(int argc, char **argv) {
  // skip argv[0]
  auto args = std::span{argv + 1, static_cast<std::size_t>(argc - 1)};

  // pre-process the command line arguments
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
    if (sp == "-h"sv) {
      print_help();
      return 0;
    }
    if (sp == "-help"sv || sp == "--help"sv) {
      print_help();
      return 1; // continuing let clang print its help list
    }
    if (sp == "-c"sv || sp == "-o"sv) {
      return 1; // continuing let clang do the compilation task
    }
  }

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
      auto opath = compile_source(argv[0], sp);
      if (fs::exists(opath)) {
        icpp::exec_main(opath.c_str());
        fs::remove(opath);
      } else {
        // if failed to compile the input source, clang has already printed the
        // errors
      }
    } else {
      // pass sp as an executable file
      icpp::exec_main(sp);
    }
  }
  return 0;
}
