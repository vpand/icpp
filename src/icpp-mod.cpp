/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "arch.h"
#include "icpp.h"
#include "imod/createcfg.h"
#include "object.h"
#include "platform.h"
#include "runcfg.h"
#include "runtime.h"
#include "utils.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/ToolOutputFile.h"
#include <llvm/Config/config.h>
#include <llvm/Config/llvm-config.h>
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
using Rtlib = icpp::RuntimeLib;

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
void init_library(std::shared_ptr<icpp::Object>) {}
ObjectDisassembler::~ObjectDisassembler() {}
void ObjectDisassembler::init(CObjectFile *, std::string_view) {}
void Object::decodeInsns(TextSection &) {}
void Object::parseSections(void) {}
extern "C" void exec_engine_main(StubContext *ctx, ContextICPP *regs) {}
int exec_main(std::string_view path, const std::vector<std::string> &deps,
              std::string_view srcpath, int iargc, char **iargv,
              bool &validcache) {
  return -1;
}
int exec_string(const char *argv0, std::string_view snippet, bool whole,
                int argc, const char **argv) {
  return -1;
}
int exec_source(const char *argv0, std::string_view path, int argc,
                const char **argv) {
  return -1;
}
} // namespace icpp

template <typename FILTER, typename PACKER>
void pack_recursively(std::string_view dstroot, std::string_view srcroot,
                      std::string_view title, FILTER filter, PACKER packer) {
#if __APPLE__
  // special process for apple framework header directory
  std::string tmpdstroot;
  if (srcroot.ends_with(".framework/Headers")) {
    tmpdstroot =
        (fs::path(dstroot) / fs::path(srcroot).parent_path().stem()).string();
    dstroot = tmpdstroot;
  }
#endif

  for (auto &entry : fs::directory_iterator(srcroot)) {
    if (entry.is_regular_file() && filter(entry.path())) {
      packer(dstroot, entry.path().string(), title);
    } else if (entry.is_directory()) {
      auto name = entry.path().filename();
      auto dst = fs::path(dstroot) / name;
      auto src = fs::path(srcroot) / name;
      pack_recursively(dst.string(), src.string(), title, filter, packer);
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
    auto assetroot = Rtlib::inst().assetRelative(cfg.name()).string();
    auto incroot = Rtlib::inst().includeRelative(cfg.name()).string();
    auto binroot = Rtlib::inst().binRelative(cfg.name()).string();
    auto libroot = Rtlib::inst().libRelative(cfg.name()).string();
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
      auto dstfile = (fs::path(dstroot) / fs::path(path).filename()).string();
      file.set_path(dstfile);
      file.set_content(buffer);
      files->Add(std::move(file));
      icpp::log_print(prefix_pack, "Packing {}.", dstfile);
      return true;
    };
    // one library packer
    auto libpacker =
        [&files, &missing](std::string_view dstroot, std::string_view prefix,
                           std::string_view path, std::string_view title) {
          auto expBuff = llvm::MemoryBuffer::getFile(path.data());
          if (!expBuff) {
            missing(title, path);
            return false;
          }

          std::string parent;
          if (prefix.size() && path.starts_with(prefix)) {
            auto dir = fs::path(path).parent_path();
            auto dirit = dir.begin();
            for (auto i : fs::path(prefix))
              dirit++;
            fs::path tmp;
            while (dirit != dir.end())
              tmp /= *dirit++;
            parent = tmp.string();
          }

          File file;
          auto buffer = expBuff.get()->getBuffer();
          auto dstfile =
              (fs::path(dstroot) / parent / fs::path(path).filename()).string();
          file.set_path(dstfile);
          file.set_content(buffer);
          files->Add(std::move(file));
          icpp::log_print(prefix_pack, "Packing library {}.", dstfile);
          return true;
        };

    // set some basic information
    pkg.set_version(icpp::version_value().value);
    pkg.set_name(cfg.name());

    // pack assets
    for (auto a : cfg.assets()) {
      if (!fs::exists(a.data())) {
        missing("Asset", a.data());
        return;
      }
      if (fs::is_regular_file(a.data())) {
        if (!packer(assetroot, a.data(), "Asset"))
          return;
        continue;
      }
      if (!fs::is_directory(a.data())) {
        icpp::log_print(prefix_error,
                        "Asset path must be a regular file or directory: {}.",
                        a.data());
        return;
      }
      pack_recursively(
          assetroot, a.data(), "Asset directory",
          [](const fs::path &file) {
            // ignore hidden file
            return file.filename().string()[0] != '.';
          },
          packer);
    }

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
            return !file.has_extension() || file.extension() == ".h" ||
                   file.extension() == ".hpp";
          },
          packer);
    }

    // pack objects
    for (auto obj : cfg.binaryObjects()) {
      if (!packer(libroot, obj.data(), "Object"))
        return;
    }

    // pack executables
    for (auto exe : cfg.binaryExecutables()) {
      if (!packer(binroot, exe.data(), "Excutable"))
        return;
    }

    // pack libraries
    auto prefix = cfg.installPrefix();
    for (auto lib : cfg.binaryLibraries()) {
      if (!libpacker(libroot, prefix.data(), lib.data(), "Library"))
        return;
    }

    // compile all the input sources to raw object and pack them
    auto imodexe = fs::path(program);
    auto icppexe = (imodexe.parent_path() /
                    (std::string("icpp") + imodexe.extension().string()))
                       .string();
    auto cfgincs = cfg.includeDirs();
    for (auto src : cfg.sources()) {
      if (!fs::exists(src.data())) {
        missing("Source", src.data());
        return;
      }
      if (!cfgincs.size()) {
        // if there's no extra include configuration, then directly pack this
        // source, this way can make an os independent icpp module cause we can
        // compile it at the installation time.
        packer(libroot, src.data(), "Source");
        continue;
      }
      std::vector<std::string> ccargs;
      auto srcpath = fs::path(src.data());
      auto objfile =
          (srcpath.parent_path() / (srcpath.stem().string() + ".o")).string();
      ccargs.push_back("-c");
      ccargs.push_back(srcpath.string());
      ccargs.push_back("-o");
      ccargs.push_back(objfile);
      for (auto inc : cfgincs)
        ccargs.push_back(std::format("-I{}", inc.data()));
      ccargs.push_back("-O2");

      icpp::log_print(prefix_prog, "Compiling {}.", srcpath.string());
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
    std::string_view sysname = "any", archname = "src";
    if (cfgincs.size()) {
      sysname = icpp::system_name(icpp::host_system());
      archname = icpp::arch_name(icpp::host_arch());
    }
    auto pkgpath = fs::path(cfgpath).parent_path() /
                   std::format("{}-{}-{}{}", cfg.name().data(), sysname,
                               archname, Rtlib::inst().packageExtension);
    std::ofstream outf(pkgpath.c_str(), std::ios::binary);
    if (!outf.is_open()) {
      icpp::log_print(prefix_error, "Failed to create the package file {}.",
                      pkgpath.string());
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
                    pkgpath.string(), compsz);
  } catch (const std::exception &e) {
    icpp::log_print(prefix_error, "{}", e.what());
  } catch (...) {
    icpp::log_print(prefix_error, "Exception occurred, failed to parse {}.",
                    cfgpath);
  }
}

static void install_package(const char *program, std::string_view pkgpath) {
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

  auto imodexe = fs::path(program);
  auto icppexe = (imodexe.parent_path() /
                  (std::string("icpp") + imodexe.extension().string()))
                     .string();
  // icpp local module repository is at $HOME/.icpp
  auto repo = Rtlib::inst().repo();
  auto modlib = Rtlib::inst().libRelative(pkg.name()).string();
  // <libname, symbol hash array>
  SymbolHash symhash;
  auto allhashes = symhash.mutable_hashes();
  for (auto &file : pkg.files()) {
    auto fullpath = repo / file.path();
    auto parent = fullpath.parent_path();
    icpp::must_exist(parent);

    std::ofstream outf(fullpath, std::ios::binary);
    if (!outf.is_open()) {
      icpp::log_print(prefix_error, "Failed to write module file {}.",
                      fullpath.string());
      return;
    }
    icpp::log_print(prefix_prog, "Installing {}...", file.path());
    outf.write(file.content().data(), file.content().size());
    outf.close(); // flush the file buffer
    if (!file.path().starts_with("lib")) {
      if (file.path().starts_with("bin")) {
        fs::permissions(fullpath,
                        fs::perms::owner_read | fs::perms::owner_exec |
                            fs::perms::group_read | fs::perms::group_exec |
                            fs::perms::others_read | fs::perms::others_exec,
                        std::filesystem::perm_options::add);
      }
      continue;
    }
    auto filename = fs::path(file.path()).filename().string();
    if (fs::path(filename).has_extension() &&
        (filename.find(LLVM_PLUGIN_EXT) == std::string::npos &&
         !filename.ends_with(icpp::obj_ext))) {
      if (icpp::is_cpp_source(filename)) {
        std::vector<std::string> ccargs;
        auto objfile = (parent / (fullpath.stem().string() + ".o")).string();
        ccargs.push_back("-c");
        ccargs.push_back(fullpath.string());
        ccargs.push_back("-o");
        ccargs.push_back(objfile);
        ccargs.push_back("-O2");

        icpp::log_print(prefix_prog, "Compiling {}.", file.path());
        proc::child compiler(icppexe, ccargs);
        compiler.wait();
        if (compiler.exit_code())
          return; // stop if failed

        icpp::log_print(prefix_prog, "Parsing the symbols of {}...",
                        file.path());
        std::string message;
        icpp::SymbolHash hasher(objfile);
        // parse and calculate the symbol hash array
        auto hashes = hasher.hashes(message);
        if (message.size()) {
          icpp::log_print(prefix_error, "{}", message);
          return;
        }
        if (!hashes.size()) {
          icpp::log_print(prefix_prog, "There's no symbol in {}.", file.path());
          continue;
        }
        auto name = fs::path(objfile).string();
        icpp::log_print(prefix_prog, "Parsed {} symbols in {}.", hashes.size(),
                        name);
        allhashes->insert(
            {name, std::string(reinterpret_cast<char *>(&hashes[0]),
                               sizeof(hashes[0]) * hashes.size())});
      }
      continue;
    }

    icpp::log_print(prefix_prog, "Parsing the symbols of {}...", file.path());
    std::string message;
    icpp::SymbolHash hasher(fullpath.string());
    // parse and calculate the symbol hash array
    auto hashes = hasher.hashes(message);
    if (message.size()) {
      icpp::log_print(prefix_error, "{}", message);
      return;
    }
    if (!hashes.size()) {
      icpp::log_print(prefix_prog, "There's no symbol in {}.", file.path());
      continue;
    }
    auto name = file.path();
    name.replace(0, modlib.size() + 1, "");
    icpp::log_print(prefix_prog, "Parsed {} symbols in {}.", hashes.size(),
                    name);
    allhashes->insert({name, std::string(reinterpret_cast<char *>(&hashes[0]),
                                         sizeof(hashes[0]) * hashes.size())});
  }

  // make sure the symbol.hash file at least contains 1 item
  allhashes->insert({pkg.name(), ""});

  // the flag of module installed by user: symbol.hash
  // even if this module only contains headers still needs to create this file,
  // it's a flag to indicate this is a valid icpp module that is installed by
  // imod, otherwise any of the libraries in its lib directory won't be loaded
  // by icpp at runtime.
  auto hashfile = (icpp::must_exist(Rtlib::inst().libFull(pkg.name())) /
                   Rtlib::inst().hashFile)
                      .string();
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
  auto asset = Rtlib::inst().assetFull(name);
  auto include = Rtlib::inst().includeFull(name);
  auto bin = Rtlib::inst().binFull(name);
  auto lib = Rtlib::inst().libFull(name);
  if (!fs::exists(include) && !fs::exists(lib)) {
    icpp::log_print(prefix_error, "There's no module: {}.", name.data());
    return;
  }
  try {
    if (fs::exists(asset))
      fs::remove_all(asset);
    if (fs::exists(include))
      fs::remove_all(include);
    if (fs::exists(bin))
      fs::remove_all(bin);
    if (fs::exists(lib))
      fs::remove_all(lib);
  } catch (std::exception &e) {
    icpp::log_print(prefix_error, "Failed to uninstall module {}: {}.",
                    name.data(), e.what());
    return;
  }
  icpp::log_print(prefix_prog, "Uninstalled module {}.", name.data());
}

static void list_module() {
  icpp::log_print(icpp::Raw, "Installed module:");
  for (auto &entry : fs::directory_iterator(Rtlib::inst().includeFull(""))) {
    if (entry.is_directory()) {
      icpp::log_print(icpp::Raw, " * {}", entry.path().filename().string());
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

  icpp::RunConfig::inst(argv[0], "");

  if (CreatePackage.length())
    create_package(argv[0], CreatePackage);
  if (InstallPath.length())
    install_package(argv[0], InstallPath);
  if (UninstallModule.length())
    uninstall_module(UninstallModule);
  if (ListModule)
    list_module();

  return 0;
}
