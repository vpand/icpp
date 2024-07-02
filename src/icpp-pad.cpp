/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "icpp.h"
#include "utils.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
#include <boost/algorithm/string.hpp>
#include <icpppad.pb.h>
#include <set>

namespace cl = llvm::cl;
namespace iopad = com::vpand::iopad;

cl::OptionCategory IOPad("ICPP Interpretable Object Launch Pad Options");

static cl::opt<std::string>
    IP("ip", cl::desc("Set the remote ip address of icpp-gadget."),
       cl::cat(IOPad));
static cl::opt<std::string> Port("port", cl::desc("Set the connection port."),
                                 cl::cat(IOPad));
static cl::opt<std::string>
    Fire("fire",
         cl::desc("Fire the input source file to the connected remote "
                  "icpp-gadget to execute it."),
         cl::cat(IOPad));
static cl::opt<bool> Repl(
    "repl",
    cl::desc("Enter into a REPL interactive shell to fire the input snippet "
             "code to the connected remote icpp-gadget to execute it."),
    cl::init(false), cl::cat(IOPad));

static void print_version(llvm::raw_ostream &os) {
  os << "ICPP (https://vpand.com/):\n  IObject Launch Pad Tool built with "
        "ICPP "
     << icpp::version_string() << "\n";
}

static void exec_code(std::string_view program, std::string_view code) {}

static int exec_repl(std::string_view program) {
  std::cout << std::format(
      "ICPP {} IOPAD mode. Copyright (c) vpand.com.\nRunning C++ in "
      "anywhere like a script.\n",
      icpp::version_string());

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
    exec_code(program, dyncodes);
    lastsnippet = snippet;
  }
  return 0;
}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);
  cl::HideUnrelatedOptions(IOPad);
  cl::AddExtraVersionPrinter(print_version);
  cl::ParseCommandLineOptions(
      argc, argv,
      std::format(
          "ICPP, Interpreting C++, running C++ in anywhere like a script.\n"
          "  IObject Launch Pad Tool built with ICPP {}",
          icpp::version_string()));
  if (Repl) {
    exec_repl(argv[0]);
  }
  return 0;
}
