/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "icpp.h"
#include "imod/createcfg.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
#include <format>
#include <isymhash.pb.h>

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

static void create_package(std::string_view cfgpath) {
  try {
    imod::CreateConfig cfg(cfgpath);
  } catch (std::invalid_argument &e) {
    std::cout << e.what() << std::endl;
  } catch (std::system_error &e) {
    std::cout << e.what() << std::endl;
  } catch (...) {
    std::cout << "Failed to parse " << cfgpath << "." << std::endl;
  }
}

static void install_package(std::string_view pkgpath) {}

static void uninstall_module(std::string_view name) {}

static void list_module() {}

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

  if (CreatePackage.length())
    create_package(CreatePackage);
  if (InstallPath.length())
    install_package(InstallPath);
  if (UninstallModule.length())
    uninstall_module(UninstallModule);
  if (ListModule)
    list_module();

  return 0;
}
