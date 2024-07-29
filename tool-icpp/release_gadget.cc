/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

/*
This is a C++ script to release the built icpp files, it'll create an
icpp release package in the following layout, icpp-gadget-vx.x.x-os-arch:
---bin
---icpp-gadget.so/dylib
---icpp-server
---[libc++_shared.so]
---lib
------boost

Usage: icpp release_gadget.cc /path/to/prefix [/path/to/strip]

The initial icpp package can be downloaded for your local system at:
https://github.com/vpand/icpp/releases
*/

#include <icpp.hpp>

// for icpp package version
#include "../src/icpp.h"

static auto log(const std::string &text) { std::puts(text.data()); }

#define log_return(text, stmt)                                                 \
  {                                                                            \
    log(text.data());                                                          \
    stmt;                                                                      \
  }

static std::string strip_path{"strip"};

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

  if (strip) {
    std::system(std::format("{} -x {} -o {}", strip_path, srcfile.string(),
                            dstfile.string())
                    .data());
    log(std::format("Packed and stripped file {}.", dstfile.string()));
    return;
  }

  std::error_code err;
  fs::copy_file(srcfile, dstfile, fs::copy_options::overwrite_existing, err);
  if (err)
    log_return(std::format("Failed to copy file: {} ==> {}, {}.",
                           srcfile.string(), dstfile.string(), err.message()),
               return);
  log(std::format("Packed file {}.", dstfile.string()));
}

static auto pack_dir(const fs::path &srcdir, const fs::path &dstroot,
                     std::string_view dstname = "", bool symlink = false) {
  auto dstdir = dstroot / (dstname.size() ? dstname : srcdir.filename());
  if (!dstname.size() && fs::exists(dstdir))
    log_return(std::format("Ignored packing {}, {} exists.", srcdir.string(),
                           dstdir.string()),
               return);
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
  if (argc == 1)
    log_return(
        std::format("Usage: {} /path/to/prefix [/path/to/strip].", argv[0]),
        return 0);
  if (argc == 3) {
    strip_path = argv[2]; // ndk strip path
    log(std::format("Using user specified strip tool {}.", strip_path));
  }

  auto projroot = fs::absolute(argv[0]).parent_path().parent_path();
  // create the destination directory if necessary
  auto dstroot = fs::path(argv[1]);
  create_dir(dstroot);

  std::string_view osnames[] = {"ios", "android", "android"};
  std::string_view archnames[] = {"arm64", "arm64-v8a", "x86_64"};
  std::string_view exts[] = {".dylib", ".so", ".so"};
  for (size_t i = 0; i < std::size(osnames); i++) {
    auto os = osnames[i];
    auto arch = archnames[i];
    auto ext = exts[i];

    // ignore this platform if there's no prebuilt boost and cxx library
    auto boostlib =
        projroot / std::format("cmake/boost/build-{}/boost/lib", arch);
    if (!fs::exists(boostlib)) {
      log(std::format("There's no {}.", boostlib.string()));
      continue;
    }
    auto cxxlib = projroot / std::format("cmake/cxxconf/build-{}/lib", arch);
    if (!fs::exists(cxxlib)) {
      log(std::format("There's no {}.", cxxlib.string()));
      continue;
    }

    // create icpp package layout
    auto pkgdir =
        std::format("icpp-gadget-v{}.{}.{}-{}-{}", icpp::version_major,
                    icpp::version_minor, icpp::version_patch, os, arch);
    auto icpproot = dstroot / pkgdir;
    auto bin = icpproot / "bin";
    auto lib = icpproot / "lib";
    create_dir(icpproot);
    create_dir(bin);
    create_dir(lib);
    create_dir(lib / "boost");
    // copy boost files
    pack_dir(boostlib / ".", lib, "boost");

    // copy cxx files
    pack_dir(cxxlib / ".", lib, ".");

    // copy icpp files
    auto libgadget = std::string("icpp-gadget") + ext.data();
    auto gadget =
        projroot / std::format("cmake/icpp-gadget/build-{}.Release", arch);
    for (auto &name : {libgadget, std::string("icpp-server")})
      pack_file(gadget / name, bin, true);

    auto targz = pkgdir + ".tar.gz";
    log(std::format("Packing icpp release package {}...", targz));
    std::system(
        std::format("cd {} && tar czf {} {}", dstroot.string(), targz, pkgdir)
            .data());
    log(std::format("Created icpp package {}.", targz));
  }

  std::puts("Done");
  return 0;
}
