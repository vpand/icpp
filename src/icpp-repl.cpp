/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "compile.h"
#include "exec.h"
#include "icpp.h"
#include "log.h"
#include "object.h"
#include "runcfg.h"
#include "utils.h"
#include <boost/algorithm/string.hpp>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

namespace icpp {

int exec_string(const char *argv0, std::string_view snippet, bool whole,
                int argc, const char **argv) {
  // construct a temporary source path
  auto srcpath = fs::temp_directory_path() / icpp::rand_filename(8, ".cc");
  std::ofstream outf(srcpath);
  if (!outf.is_open()) {
    log_print(Runtime, "Failed to create a temporary source file {}.",
              srcpath.string());
    return -1;
  }
  if (whole)
    outf << snippet.data();
  else
    outf << "#include <icpp.hpp>\nint main(void) {" << snippet.data()
         << ";return 0;}";
  outf.close();

  std::vector<const char *> incs;
  auto opath = compile_source_icpp(argv0, srcpath.string(), "-O1", incs);
  if (!fs::exists(opath))
    return -1; // clang has printed the error message

  std::vector<std::string> deps;
  int iargc = 1;
  const char **iarg = &argv0;
  if (argc) {
    iargc = argc;
    iarg = argv;
  }
  bool validcache;
  int exitcode = exec_main(opath.string(), deps, srcpath.string(), iargc,
                           const_cast<char **>(iarg), validcache);
  fs::remove(opath);
  return exitcode;
}

int exec_source(const char *argv0, std::string_view path, int argc,
                const char **argv) {
  std::vector<std::string> deps;
  std::vector<const char *> incs;
  bool validcache;
  int exitcode = -1;
  while (true) {
    // compile the input source to be as the running host object file(.o,
    // .obj)
    auto opath = icpp::compile_source_icpp(argv0, path, "-O1", incs);
    if (fs::exists(opath)) {
      int iargc = 1;
      const char **iarg = &argv0;
      if (argc) {
        iargc = argc;
        iarg = argv;
      }
      exitcode = icpp::exec_main(opath.string(), deps, path, iargc,
                                 const_cast<char **>(iarg), validcache);
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
  return exitcode;
}

int exec_repl(const char *argv0) {
  std::cout << std::format("ICPP {}. Copyright (c) vpand.com.\nRunning C++ in "
                           "anywhere like a script.\n",
                           version_string());
  RunConfig::repl = true;
  RunConfig::inst(argv0, "");
  return icpp::repl_entry(
      [&](std::string_view dyncode) { exec_string(argv0, dyncode, true); });
}

} // namespace icpp
