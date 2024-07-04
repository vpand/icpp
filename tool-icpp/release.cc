/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

/*
This is a C++ script to release the current running icpp, it'll create an
icpp release package in the following layout:
---bin
------icpp
------icpp.so/dll/dylib
------icpp-gadget.so/dll/dylib
------imod
------iopad
---include
------boost
---lib
------boost

usage: build/src/icpp release.cc /path/to/prefix
*/

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <iostream>
#include <string_view>
#include <vector>

// for icpp package version
#include "../src/icpp.h"
// for llvm version
#include "../build/third/llvm-project/llvm/include/llvm/Config/llvm-config.h"

#if __APPLE__
#define LIBEXT ".dylib"
#elif __linux__
#define LIBEXT ".so"
#else
#define LIBEXT ".dll"
#endif

#if _WIN32
#define EXEEXT ".exe"
#define VERSEP "-"
#define ICPPRT "icpp" LIBEXT
#else
#define EXEEXT ""
#define VERSEP "."
#define ICPPRT std::format("icpp" VERSEP "{}" LIBEXT, LLVM_VERSION_MAJOR)
#endif

namespace fs = std::filesystem;

static auto log(const std::string &text) { std::puts(text.data()); }

static auto log_exit(const std::string &text) {
  log(text.data());
  std::exit(-1);
}

static auto create_dir(const fs::path &path) {
  if (fs::exists(path))
    return;
  if (!fs::create_directory(path))
    log_exit(std::format("Failed to create directory: {}.", path.string()));
  log(std::format("Created directory {}.", path.string()));
}

static auto pack_file(const fs::path &srcfile, const fs::path &dstdir,
                      bool strip) {
  auto dstfile = dstdir / srcfile.filename();
  std::error_code err;
  fs::copy_file(srcfile, dstfile, fs::copy_options::overwrite_existing, err);
  if (err)
    log_exit(std::format("Failed to copy file: {} ==> {}, {}.",
                         srcfile.string(), dstfile.string(), err.message()));

#if __APPLE__ || __linux__
  if (strip) {
    std::system(std::format(R"(strip -x "{}")", dstfile.string()).data());
    log(std::format("Packed and stripped file {}.", dstfile.string()));
    return;
  }
#endif

  log(std::format("Packed file {}.", dstfile.string()));
}

static auto pack_dir(const fs::path &srcdir, const fs::path &dstroot) {
  auto dstdir = dstroot / srcdir.filename();
  std::error_code err;
  fs::copy(srcdir, dstdir,
           fs::copy_options::overwrite_existing | fs::copy_options::recursive |
               fs::copy_options::skip_symlinks,
           err);
  if (err)
    log_exit(std::format("Failed to copy directory: {} ==> {}, {}.",
                         srcdir.string(), dstdir.string(), err.message()));
  else
    log(std::format("Packed directory {} from {}.", dstdir.string(),
                    srcdir.string()));
}

int main(int argc, char **argv) {
  if (argc != 2)
    log_exit(std::format("Usage: {} /path/to/prefix.", argv[0]));

  // create the destination directory if necessary
  auto dst = fs::path(argv[1]);
  create_dir(dst);

  // create package layout
  auto thisfile = fs::absolute(argv[0]);
  auto srcroot = thisfile.parent_path() / "../build-release/src";
  auto pkgroot = dst / std::format("icpp-v{}.{}.{}", icpp::version_major,
                                   icpp::version_minor, icpp::version_patch);
  auto bin = pkgroot / "bin";
  auto include = pkgroot / "include";
  auto lib = pkgroot / "lib";
  create_dir(pkgroot);
  create_dir(bin);
  create_dir(include);
  create_dir(lib);

  // copy icpp files
  std::vector<std::string> names = {
      "icpp" EXEEXT,        ICPPRT, "imod" EXEEXT, "iopad" EXEEXT,
      "icpp-gadget" LIBEXT,
  };
  for (auto &name : names)
    pack_file(srcroot / name, bin, true);

  // copy clang files
  pack_dir(srcroot / "../third/llvm-project/llvm/lib/clang", lib);

  // copy boost files
  auto boost = srcroot / "../boost";
  auto boostinc = boost / "include";
  auto boostlib = boost / "lib";
  if (fs::exists(boostinc) && fs::exists(boostlib)) {
    pack_dir(boostinc, pkgroot);
    pack_dir(boostlib, pkgroot);
  } else {
    log(std::format("Can't find boost in {}, skipped packing boost.",
                    boost.string()));
  }

  puts("Done.");
  return 0;
}
