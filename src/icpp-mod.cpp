/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "icpp.h"
#include "imod/createcfg.h"
#include "object.h"
#include "platform.h"
#include "utils.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
#ifdef ON_WINDOWS
#include <boost/process.hpp>
#else
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <boost/process.hpp>
#pragma clang diagnostic pop
#endif // end of ON_WINDOWS
#include <brotli/decode.h>
#include <brotli/encode.h>
#include <filesystem>
#include <fstream>
#include <icppmod.pb.h>
#include <isymhash.pb.h>

namespace proc = boost::process;
namespace fs = std::filesystem;
namespace cl = llvm::cl;

using Package = com::vpand::imod::MoudlePackage;
using File = com::vpand::imod::File;
using SymbolHash = com::vpand::imod::SymbolHash;

static std::string_view prefix_pack(" + ");
static std::string_view prefix_prog(" | ");
static std::string_view prefix_error(" x ");

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

// Don't need these implementations at all in imod tool
namespace icpp {
void init_library(std::__1::shared_ptr<icpp::Object>) {}
ObjectDisassembler::~ObjectDisassembler() {}
void ObjectDisassembler::init(CObjectFile *, std::string_view) {}
void Object::decodeInsns(TextSection &) {}
} // namespace icpp

template <typename FILTER, typename PACKER>
void pack_recursively(std::string_view dstroot, std::string_view srcroot,
                      std::string_view title, FILTER filter, PACKER packer) {
  for (auto &entry : fs::recursive_directory_iterator(srcroot)) {
    if (entry.is_regular_file() && filter(entry.path())) {
      packer(dstroot, entry.path().c_str(), title);
    } else if (entry.is_directory()) {
      auto name = entry.path().filename();
      auto dst = fs::path(dstroot) / name;
      auto src = fs::path(srcroot) / name;
      pack_recursively(dst.c_str(), src.c_str(), title, filter, packer);
    }
  }
};

struct icpp_package_header_t {
  uint32_t magic; // "icpp" magic value
  uint32_t size;  // original size before compression
};

static void create_package(const char *program, std::string_view cfgpath) {
  try {
    Package pkg;
    imod::CreateConfig cfg(cfgpath);
    auto files = pkg.mutable_files();
    auto incroot = std::format("include/icpp/{}/", cfg.name().data());
    auto libroot = std::format("lib/{}/", cfg.name().data());
    auto missing = [](std::string_view title, std::string_view item) {
      icpp::log_print(
          prefix_error,
          "{} {} doesn't exist, make sure it can be accessed in {}.", title,
          item, fs::current_path().string());
    };
    // one file packer
    auto packer = [&files, &missing](std::string_view dstroot,
                                     std::string_view path,
                                     std::string_view title) {
      auto expBuff = llvm::MemoryBuffer::getFile(path.data());
      if (!expBuff) {
        missing(title, path);
        return false;
      }

      File file;
      auto buffer = expBuff.get()->getBuffer();
      auto dstfile = std::string(dstroot) + fs::path(path).filename().string();
      file.set_path(dstfile);
      file.set_content(buffer);
      files->Add(std::move(file));
      icpp::log_print(prefix_pack, "Packing {}.", dstfile);
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
    icpp::log_print(prefix_prog, "Built a new package with raw size: {}.",
                    pkgbuff.size());

    // compress the raw package buffer
    auto maxcompsz = BrotliEncoderMaxCompressedSize(pkgbuff.size());
    auto compsz = maxcompsz;
    std::vector<uint8_t> compbuff(maxcompsz);
    icpp::log_print(prefix_prog,
                    "Compressing the package buffer with brotli...");
    if (!BrotliEncoderCompress(
            BROTLI_DEFAULT_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_DEFAULT_MODE,
            pkgbuff.size(), reinterpret_cast<const uint8_t *>(pkgbuff.data()),
            &compsz, &compbuff[0])) {
      icpp::log_print(prefix_error, "Failed to compress the package buffer.");
      return;
    }

    // done.
    auto pkgpath = fs::path(cfgpath).parent_path() /
                   std::format("{}.icpp", cfg.name().data());
    std::ofstream outf(pkgpath.c_str(), std::ios::binary);
    if (!outf.is_open()) {
      icpp::log_print(prefix_error, "Failed to create the package file {}.",
                      pkgpath.c_str());
      return;
    }
    // write icpp module magic value
    icpp_package_header_t pkghdr{imod::module_magic,
                                 static_cast<uint32_t>(pkgbuff.size())};
    outf.write(reinterpret_cast<const char *>(&pkghdr), sizeof(pkghdr));
    // write the compressed buffer
    outf.write(reinterpret_cast<const char *>(&compbuff[0]), compsz);
    icpp::log_print(prefix_prog,
                    "Successfully created {} with compressed size: "
                    "{}.",
                    pkgpath.c_str(), compsz);
  } catch (std::invalid_argument &e) {
    icpp::log_print(prefix_error, "{}", e.what());
  } catch (std::system_error &e) {
    icpp::log_print(prefix_error, "{}", e.what());
  } catch (...) {
    icpp::log_print(prefix_error, "Failed to parse {}.", cfgpath);
  }
}

static void install_package(std::string_view pkgpath) {
  auto expBuff = llvm::MemoryBuffer::getFile(pkgpath.data());
  if (!expBuff) {
    icpp::log_print(prefix_error, "Failed to open {}.", pkgpath.data());
    return;
  }
  auto bufferhdr = reinterpret_cast<const icpp_package_header_t *>(
      expBuff.get()->getBuffer().data());
  if (bufferhdr->magic != imod::module_magic) {
    icpp::log_print(prefix_error,
                    "The input file {} isn't an icpp module package.",
                    pkgpath.data());
    return;
  }
  // decompress
  std::vector<uint8_t> origbuf(bufferhdr->size);
  size_t decodedsz = bufferhdr->size;
  icpp::log_print(prefix_prog, "Decompressing package buffer...");
  if (!BrotliDecoderDecompress(expBuff.get()->getBufferSize() -
                                   sizeof(bufferhdr),
                               reinterpret_cast<const uint8_t *>(&bufferhdr[1]),
                               &decodedsz, &origbuf[0])) {
    icpp::log_print(prefix_error,
                    "Failed to decompress the input package buffer.");
    return;
  }

  Package pkg;
  // load package data
  if (!pkg.ParseFromArray(&origbuf[0], origbuf.size())) {
    icpp::log_print(prefix_error, "Failed to parse package buffer.");
    return;
  }
  if (pkg.version() != icpp::version_value().value) {
    icpp::log_print(prefix_error,
                    "The version of the package creator doesn't match current "
                    "imod, {} is expected.",
                    icpp::version_string());
    return;
  }
  icpp::log_print(prefix_prog, "Installing module {}...", pkg.name());

  // icpp local module repository is at $HOME/.icpp
  auto repo = fs::path(icpp::home_directory()) / ".icpp";
  if (!fs::exists(repo)) {
    if (!fs::create_directory(repo)) {
      icpp::log_print(prefix_error,
                      "Failed to create icpp module home repository {}.",
                      repo.c_str());
      return;
    }
  }

  // <name, symbol hash array>
  SymbolHash symhash;
  auto allhashes = symhash.mutable_hashes();
  for (auto &file : pkg.files()) {
    auto fullpath = repo / file.path();
    auto parent = fullpath.parent_path();
    if (!fs::exists(parent)) {
      if (!fs::create_directories(parent)) {
        icpp::log_print(prefix_error, "Failed to create module directory {}.",
                        parent.c_str());
        return;
      }
    }
    std::ofstream outf(fullpath, std::ios::binary);
    if (!outf.is_open()) {
      icpp::log_print(prefix_error, "Failed to write module file {}.",
                      fullpath.c_str());
      return;
    }
    icpp::log_print(prefix_prog, "Installing {}...", file.path().c_str());
    outf.write(file.content().data(), file.content().size());
    outf.close(); // flush the file buffer
    if (!file.path().starts_with("lib"))
      continue;

    icpp::log_print(prefix_prog, "Parsing the symbols of {}...",
                    file.path().c_str());
    std::string message;
    icpp::SymbolHash hasher(fullpath.c_str());
    // parse and calculate the symbol hash array
    auto hashes = hasher.hashes(message);
    if (!hashes.size()) {
      icpp::log_print(prefix_error, "{}", message);
      return;
    }
    auto name = fullpath.filename().string();
    icpp::log_print(prefix_prog, "Parsed {} symbols in {}.", hashes.size(),
                    name);
    allhashes->insert({name, std::string(reinterpret_cast<char *>(&hashes[0]),
                                         sizeof(hashes[0]) * hashes.size())});
  }

  // success flag: symbol.hash created
  auto hashfile = (repo / "lib" / pkg.name() / "symbol.hash").string();
  std::ofstream outf(hashfile, std::ios::binary);
  if (!outf.is_open()) {
    icpp::log_print(prefix_error, "Failed to create {}.", hashfile);
    return;
  }
  symhash.SerializePartialToOstream(&outf);
  icpp::log_print(prefix_prog, "Created {}.\n + Successfully installed {}.",
                  hashfile, pkg.name());
}

static void uninstall_module(std::string_view name) {
  auto repo = fs::path(icpp::home_directory()) / ".icpp";
  auto include = repo / "include" / "icpp" / name.data();
  auto lib = repo / "lib" / name.data();
  if (!fs::exists(include) && !fs::exists(lib)) {
    icpp::log_print(prefix_error, "There's no module: {}.", name.data());
    return;
  }
  if (fs::exists(include))
    fs::remove_all(include);
  if (fs::exists(lib))
    fs::remove_all(lib);
  icpp::log_print(prefix_prog, "Uninstalled module {}.", name.data());
}

static void list_module() {
  auto repo = fs::path(icpp::home_directory()) / ".icpp";
  auto include = repo / "include" / "icpp";
  icpp::log_print(icpp::Raw, "Installed module:");
  for (auto &entry : fs::directory_iterator(include)) {
    if (entry.is_directory()) {
      icpp::log_print(icpp::Raw, " * {}", entry.path().filename().c_str());
    }
  }
}

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
