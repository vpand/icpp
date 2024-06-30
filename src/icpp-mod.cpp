/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "icpp.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
#include <format>

using namespace llvm;

cl::OptionCategory IModCat("ICPP Module Manager Options");

static cl::opt<std::string>
    InstallPath("install", cl::desc("Install an icpp package file."),
                cl::cat(IModCat));
static cl::opt<std::string>
    UninstallModule("uninstall", cl::desc("Uninstall an installed module."),
                    cl::cat(IModCat));
static cl::opt<std::string> CreatePackage(
    "create",
    cl::desc("Create an icpp package from a json configuration file."),
    cl::cat(IModCat));
static cl::opt<bool> ListModule("list",
                                cl::desc("List all the installed modules."),
                                cl::init(false), cl::cat(IModCat));

static void print_version(raw_ostream &os) {
  os << "ICPP (https://vpand.com/):\n  IObject Module Manager Tool built with "
        "ICPP "
     << icpp::version_string() << "\n";
}

int main(int argc, char **argv) {
  InitLLVM X(argc, argv);
  cl::HideUnrelatedOptions(IModCat);
  cl::AddExtraVersionPrinter(print_version);
  cl::ParseCommandLineOptions(
      argc, argv,
      std::format(
          "ICPP, Interpreting C++, running C++ in anywhere like a script.\n"
          "  IObject Module Manager Tool built with ICPP {}",
          icpp::version_string()));
  return 0;
}
