/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

/*
This is a C++ script to release the built icpp files, it'll create an
icpp release package in the following layout, icpp-vx.x.x-os-arch:
---bin
------icpp
------icpp.so/dll/dylib
------icpp-gadget.so/dll/dylib
------icpp-server
------imod
------iopad
------libc++.so/dll/dylib
---include
------apple/win
------boost
------c
------c++
------icpp.hpp
------icppex.hpp
---lib
------clang
------boost

Usage: icpp release.cc /path/to/build /path/to/prefix

The initial icpp package can be downloaded for your local system at:
https://github.com/vpand/icpp/releases
*/

// for icpp package version
#include "../src/icpp.h"
// for llvm version
#include "../build/third/llvm-project/llvm/include/llvm/Config/llvm-config.h"

// for standard c++ definitions
import std;
namespace fs = std::filesystem;

#if __APPLE__
#define LIBEXT ".dylib"
constexpr const std::string_view os = "apple";
constexpr const std::string_view libcpp = "libc++.1.0" LIBEXT;
constexpr const std::string_view libcppabi = "libc++abi.1.0" LIBEXT;
constexpr const std::string_view libunwind = "libunwind.1.0" LIBEXT;
#elif __linux__
#define LIBEXT ".so"
constexpr const std::string_view os = "linux";
constexpr const std::string_view libcpp = "libc++" LIBEXT ".1.0";
constexpr const std::string_view libcppabi = "libc++abi" LIBEXT ".1.0";
constexpr const std::string_view libunwind = "libunwind" LIBEXT ".1.0";
#else
#define LIBEXT ".dll"
constexpr const std::string_view os = "win";
constexpr const std::string_view libcpp = "c++" LIBEXT;
#endif

#if __aarch64__ || __arm64__
#if __linux__
constexpr const std::string_view arch = "aarch64";
#else
constexpr const std::string_view arch = "arm64";
#endif
#else
constexpr const std::string_view arch = "x86_64";
#endif

#if _WIN32
#define EXEEXT ".exe"
#define VERSEP "-"
#define ICPPRT "icpp" LIBEXT
#else
#define EXEEXT ""
#define VERSEP "."
#if __APPLE__
#define ICPPRT std::format("icpp" VERSEP "{}" LIBEXT, LLVM_VERSION_MAJOR)
#else
#define ICPPRT std::format("icpp" LIBEXT VERSEP "{}", LLVM_VERSION_MAJOR)
#endif
#endif

// the final libc++ dynamic library name used by icpp runtime
#if _WIN32
constexpr const std::string_view libcpp_name = "c++" LIBEXT;
#else
constexpr const std::string_view libcpp_name = "libc++" LIBEXT;
#endif
constexpr const std::string_view libcppabi_name = "libc++abi.1" LIBEXT;
constexpr const std::string_view libunwind_name = "libunwind.1" LIBEXT;

static auto log(const std::string &text) { std::puts(text.data()); }

#define log_return(text, stmt)                                                 \
  {                                                                            \
    log(text.data());                                                          \
    stmt;                                                                      \
  }

static auto create_dir(const fs::path &path) {
  if (fs::exists(path))
    return;
  if (!fs::create_directory(path))
    log_return(std::format("Failed to create directory: {}.", path.string()),
               return);
  log(std::format("Created directory {}.", path.string()));
}

static auto pack_file(const fs::path &srcfile, const fs::path &dstdir,
                      bool strip, std::string_view dstname = "") {
  if (!fs::exists(srcfile)) {
    log(std::format("There's no {}, ignored packing it.", srcfile.string()));
    return;
  }

  auto dstfile =
      dstdir / (dstname.size() ? fs::path(dstname) : srcfile.filename());
  std::error_code err;
  fs::copy_file(srcfile, dstfile, fs::copy_options::overwrite_existing, err);
  if (err)
    log_return(std::format("Failed to copy file: {} ==> {}, {}.",
                           srcfile.string(), dstfile.string(), err.message()),
               return);

#if __APPLE__ || __linux__
  if (strip) {
    std::system(std::format(R"(strip -x "{}")", dstfile.string()).data());
    log(std::format("Packed and stripped file {}.", dstfile.string()));
    return;
  }
#endif

  log(std::format("Packed file {}.", dstfile.string()));
}

static auto pack_dir(const fs::path &srcdir, const fs::path &dstroot,
                     bool symlink = false) {
  auto dstdir = dstroot / srcdir.filename();
  std::error_code err;
  auto option =
      fs::copy_options::overwrite_existing | fs::copy_options::recursive;
  if (symlink)
    option |= fs::copy_options::copy_symlinks;
  else
    option |= fs::copy_options::skip_symlinks;
  fs::copy(srcdir, dstdir, option, err);
  if (err)
    log(std::format("Failed to copy directory: {} ==> {}, {}.", srcdir.string(),
                    dstdir.string(), err.message()));
  else
    log(std::format("Packed directory {} from {}.", dstdir.string(),
                    srcdir.string()));
}

int main(int argc, char **argv) {
  if (argc != 3)
    log_return(
        std::format("Usage: {} /path/to/build /path/to/prefix.", argv[0]),
        return -1);

  // where the built outputs placed
  auto srcroot = fs::path(argv[1]) / "src";
  // create the destination directory if necessary
  auto dstroot = fs::path(argv[2]);
  create_dir(dstroot);
  // create icpp package layout
  auto icpproot =
      dstroot / std::format("icpp-v{}.{}.{}-{}-{}", icpp::version_major,
                            icpp::version_minor, icpp::version_patch, os, arch);
  auto bin = icpproot / "bin";
  auto include = icpproot / "include";
  auto lib = icpproot / "lib";
  create_dir(icpproot);
  create_dir(bin);
  create_dir(include);
  create_dir(lib);

  // copy icpp files
  std::vector<std::string_view> names = {
      "icpp" EXEEXT,        ICPPRT,
      "imod" EXEEXT,        "iopad" EXEEXT,
      "icpp-gadget" LIBEXT, "icpp-server" EXEEXT,
  };
  for (auto &name : names)
    pack_file(srcroot / name, bin, true);

  // copy libc++ file
#if __APPLE__
  pack_file(srcroot / "../libcxx/lib" / libcpp, lib, true, libcpp_name);
  pack_file(srcroot / "../libcxx/lib" / libcppabi, lib, true, libcppabi_name);
  pack_file(srcroot / "../libcxx/lib" / libunwind, lib, true, libunwind_name);
#elif __linux__
  auto libcxx = srcroot / std::format("../llvm/lib/{}-unknown-linux-gnu", arch);
  pack_file(libcxx / libcpp, lib, true, libcpp_name);
  pack_file(libcxx / libcppabi, lib, true, libcppabi_name);
  pack_file(libcxx / libunwind, lib, true, libunwind_name);
  std::system(
      std::format("cd {}; ln -s {} {}", lib.string(), libcpp_name, libcpp)
          .data());
#else
  pack_file(srcroot / "../libcxx/Release/lib/Release" / libcpp, lib, false);
  pack_file(srcroot / "../../cmake/boost/demangle/build/demangle.dll", lib,
            false);
  // create the clang-cl magic file for msvc cl building
  std::ofstream outf(lib / "clang-cl");
  outf << "icpp internal flag file for windows platform.";
#endif

  // copy c/c++/os headers
  std::vector<std::string_view> incnames = {
      os,
      "include/c",
      "include/c++",
  };
  for (auto &name : incnames) {
    auto srcdir = srcroot / "../../runtime" / name;
    if (fs::exists(srcdir))
      pack_dir(srcdir, include, true);
    else
      log(std::format("There's no {}, ignored packing it.", srcdir.string()));
  }
  pack_file(srcroot / "../../runtime/include/icpp.hpp", include, false);
  pack_file(srcroot / "../../runtime/include/icppex.hpp", include, false);

  // copy clang files
  pack_dir(srcroot / "../third/llvm-project/llvm/lib/clang", lib);

  // copy boost files
  auto boost = srcroot / "../boost";
#if _WIN32
  auto boostinc = boost / "include/boost-1_86";
  auto boostlib = boost / "bin";
#else
  auto boostinc = boost / "include";
  auto boostlib = boost / "lib";
#endif
  if (fs::exists(boostinc) && fs::exists(boostlib)) {
    auto icppboostlib = lib / "boost";
    create_dir(icppboostlib);
    pack_dir(boostinc / ".", icpproot);
    pack_dir(boostlib / ".", icppboostlib);
  } else {
    log(std::format("Can't find boost in {}, skipped packing boost.",
                    boost.string()));
  }

  std::puts("Done.");
  return 0;
}
