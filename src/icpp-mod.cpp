/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "icpp.h"
#include "imod/createcfg.h"
#include "log.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
#ifdef _WIN32
#include <boost/process.hpp>
#else
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <boost/process.hpp>
#pragma clang diagnostic pop
#endif // end of _WIN32
#include <brotli/encode.h>
#include <filesystem>
#include <fstream>
#include <icppmod.pb.h>
#include <isymhash.pb.h>

namespace proc = boost::process;
namespace fs = std::filesystem;
namespace cl = llvm::cl;

static std::string_view pack_prefix(" + ");
static std::string_view erro_prefix(" x ");
static std::string_view prog_prefix(" | ");

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

static void print_version(llvm::raw_ostream &os) {
  os << "ICPP (https://vpand.com/):\n  IObject Module Manager Tool built with "
        "ICPP "
     << icpp::version_string() << "\n";
}

template <typename FILTER, typename PACKER>
void pack_recursively(std::string_view dstroot, std::string_view srcroot,
                      std::string_view title, FILTER filter, PACKER packer) {
  for (auto &entry : fs::recursive_directory_iterator(srcroot)) {
    if (entry.is_regular_file() && filter(entry.path())) {
      auto file = srcroot / entry.path();
      packer(dstroot, file.c_str(), title);
    } else if (entry.is_directory()) {
      auto dst = fs::path(dstroot) / entry.path();
      auto src = fs::path(srcroot) / entry.path();
      pack_recursively(dst.c_str(), src.c_str(), title, filter, packer);
    }
  }
};

static void create_package(const char *program, std::string_view cfgpath) {
  using Package = com::vpand::imod::MoudlePackage;
  using File = com::vpand::imod::File;
  try {
    Package pkg;
    imod::CreateConfig cfg(cfgpath);
    auto files = pkg.mutable_files();
    auto incroot = std::format("include/icpp/{}/", cfg.name().data());
    auto libroot = std::format("lib/{}/", cfg.name().data());
    auto missing = [](std::string_view title, std::string_view item) {
      icpp::log_print(
          erro_prefix,
          "{} {} doesn't exist, make sure it can be accessed in {}.", title,
          item, fs::current_path().string());
    };
    // one file packer
    auto packer = [&files, &missing](std::string_view dstroot,
                                     std::string_view path,
                                     std::string_view title) {
      std::ifstream inf(path, std::ios::binary | std::ios::ate);
      if (!inf.is_open()) {
        missing(title, path);
        return false;
      }
      std::string buffer(inf.tellg(), '\0');
      inf.seekg(std::ios::beg);
      inf.read(const_cast<char *>(buffer.data()), buffer.size());

      File file;
      auto dstfile = std::string(dstroot) + fs::path(path).filename().string();
      file.set_path(dstfile);
      file.set_content(buffer);
      files->Add(std::move(file));
      icpp::log_print(pack_prefix, "Packing {}.", dstfile);
      return true;
    };

    // set some basic information
    pkg.set_version(icpp::version_value().value);
    pkg.set_name(cfg.name());

    // pack headers
    for (auto hdr : cfg.headers()) {
      if (!packer(incroot, hdr.data(), "Header"))
        return;
    }

    // pack header directories
    for (auto dir : cfg.headerDirs()) {
      if (!fs::exists(dir.data())) {
        missing("Header directory", dir.data());
        return;
      }
      pack_recursively(
          incroot, dir.data(), "Header directory",
          [](const fs::path &file) {
            return file.extension() == ".h" || file.extension() == ".hpp";
          },
          packer);
    }

    // pack objects
    for (auto obj : cfg.binaryObjects()) {
      if (!packer(libroot, obj.data(), "Object"))
        return;
    }

    // pack libraries
    for (auto lib : cfg.binaryLibraries()) {
      if (!packer(libroot, lib.data(), "Library"))
        return;
    }

    // compile all the input sources to raw object and pack them
    auto imodexe = fs::path(program);
    auto icppexe = (imodexe.parent_path() /
                    (std::string("icpp") + imodexe.extension().string()))
                       .string();
    for (auto src : cfg.sources()) {
      if (!fs::exists(src.data())) {
        missing("Source", src.data());
        return;
      }
      std::vector<std::string> ccargs;
      auto srcpath = fs::path(src.data());
      auto objfile =
          (srcpath.parent_path() / (srcpath.stem().string() + ".o")).string();
      ccargs.push_back("-c");
      ccargs.push_back(srcpath.string());
      ccargs.push_back("-o");
      ccargs.push_back(objfile);
      for (auto inc : cfg.includeDirs())
        ccargs.push_back(std::format("-I{}", inc.data()));
      ccargs.push_back("-O2");

      proc::child compiler(icppexe, ccargs);
      compiler.wait();
      if (compiler.exit_code())
        return; // stop if failed
      packer(libroot, objfile, "Source");
      fs::remove(objfile);
    }

    // serialize the package instance
    auto pkgbuff = pkg.SerializeAsString();
    icpp::log_print(prog_prefix, "Built a new package with raw size: {}.",
                    pkgbuff.size());

    // compress the raw package buffer
    auto maxcompsz = BrotliEncoderMaxCompressedSize(pkgbuff.size());
    auto compsz = maxcompsz;
    std::vector<uint8_t> compbuff(maxcompsz);
    icpp::log_print(prog_prefix,
                    "Compressing the package buffer with brotli...");
    if (!BrotliEncoderCompress(
            BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
            pkgbuff.size(), reinterpret_cast<const uint8_t *>(pkgbuff.data()),
            &compsz, &compbuff[0])) {
      icpp::log_print(erro_prefix, "Failed to compress the package buffer.");
      return;
    }

    // done.
    auto pkgpath = fs::path(cfgpath).parent_path() /
                   std::format("{}.icpp", cfg.name().data());
    std::ofstream outf(pkgpath.c_str(), std::ios::binary);
    if (!outf.is_open()) {
      icpp::log_print(erro_prefix, "Failed to create the package file {}.",
                      pkgpath.c_str());
      return;
    }
    // write icpp module magic value
    outf.write(reinterpret_cast<const char *>(&imod::module_magic),
               sizeof(imod::module_magic));
    // write the compressed buffer
    outf.write(reinterpret_cast<const char *>(&compbuff[0]), compsz);
    icpp::log_print(prog_prefix,
                    "Successfully created {} with compressed size: "
                    "{}.",
                    pkgpath.c_str(), compsz);
  } catch (std::invalid_argument &e) {
    icpp::log_print(erro_prefix, "{}", e.what());
  } catch (std::system_error &e) {
    icpp::log_print(erro_prefix, "{}", e.what());
  } catch (...) {
    icpp::log_print(erro_prefix, "Failed to parse {}.", cfgpath);
  }
}

static void install_package(std::string_view pkgpath) {}

static void uninstall_module(std::string_view name) {}

static void list_module() {}

int main(int argc, char **argv) {
  llvm::InitLLVM X(argc, argv);
  cl::HideUnrelatedOptions(IModCat);
  cl::AddExtraVersionPrinter(print_version);
  cl::ParseCommandLineOptions(
      argc, argv,
      std::format(
          "ICPP, Interpreting C++, running C++ in anywhere like a script.\n"
          "  IObject Module Manager Tool built with ICPP {}",
          icpp::version_string()));

  if (CreatePackage.length())
    create_package(argv[0], CreatePackage);
  if (InstallPath.length())
    install_package(InstallPath);
  if (UninstallModule.length())
    uninstall_module(UninstallModule);
  if (ListModule)
    list_module();

  return 0;
}
