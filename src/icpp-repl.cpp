/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "compile.h"
#include "exec.h"
#include "icpp.h"
#include "log.h"
#include "runcfg.h"
#include "utils.h"
#include <boost/algorithm/string.hpp>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

namespace icpp {

void exec_string(const char *argv0, std::string_view snippet, bool whole) {
  RunConfig::repl = true;

  // construct a temporary source path
  auto srcpath = fs::temp_directory_path() / icpp::rand_filename(8, ".cc");
  std::ofstream outf(srcpath);
  if (!outf.is_open()) {
    log_print(Runtime, "Failed to create a temporary source file {}.",
              srcpath.c_str());
    return;
  }
  if (whole)
    outf << snippet.data();
  else
    outf << "int main(void) {" << snippet.data() << ";return 0;}";
  outf.close();

  std::vector<const char *> incs;
  auto opath = compile_source(argv0, srcpath.c_str(), "-O1", incs);
  if (!fs::exists(opath))
    return; // clang has printed the error message

  std::vector<std::string> deps;
  int iargc = 1;
  const char *iarg[] = {""};
  exec_main(opath.c_str(), deps, srcpath.c_str(), iargc,
            reinterpret_cast<char **>(&iarg));
  fs::remove(opath);
}

int exec_repl(const char *argv0) {
  std::cout << std::format("ICPP {}. Copyright (c) vpand.com.\nRunning C++ in "
                           "anywhere like a script.\n",
                           version_string());

  std::set<std::string> directives;
  std::string lastsnippet;
  while (!std::cin.eof()) {
    std::string snippet;
    std::cout << ">>> ";
    std::getline(std::cin, snippet);
    boost::trim<std::string>(snippet);
    if (!snippet.length()) {
      if (!lastsnippet.length())
        continue;
      // repeat the last snippet if nothing input
      snippet = lastsnippet;
    }

    // only support ascii snippet input
    bool valid = true;
    for (auto c : snippet) {
      if (!std::isprint(c)) {
        valid = false;
        break;
      }
    }
    if (!valid) {
      std::cout << "Ignored this non ascii snippet code: " << snippet
                << std::endl;
      continue;
    }

    if (snippet.starts_with("#")) {
      // accumulated compiler directives, like #include, #define, etc.
      directives.insert(snippet);
      continue;
    }

    std::string dyncodes;
    // the # prefixed compiler directives
    for (auto &d : directives)
      dyncodes += d + "\n";
    // the main entry
    dyncodes += "int main(void) {" + snippet + ";return 0;}";
    exec_string(argv0, dyncodes, true);
    lastsnippet = snippet;
  }
  return 0;
}

} // namespace icpp
