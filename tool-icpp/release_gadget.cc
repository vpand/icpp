// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

/*
This is a C++ script to release the built icpp files, it'll create an
icpp release package in the following layout, icpp-gadget-vx.x.x-os-arch:
---bin
------icpp-gadget.so/dylib
------icpp-server
---lib
------libc++.so/dll/dylib

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

static auto create_dir(const fs::path &path) {
  if (fs::exists(path))
    return;
  if (!fs::create_directories(path))
    log_return(std::format("Failed to create directory: {}.", path.string()),
               return);
  log(std::format("Created directory {}.", path.string()));
}

static auto pack_file(const fs::path &srcfile, const fs::path &dstdir,
                      std::string_view strip, std::string_view dstname = "") {
  if (!fs::exists(srcfile)) {
    log(std::format("There's no {}, ignored packing it.", srcfile.string()));
    return;
  }
  auto dstfile =
      dstdir / (dstname.size() ? fs::path(dstname) : srcfile.filename());

  std::system(
      std::format("{} -x {} -o {}", strip, srcfile.string(), dstfile.string())
          .data());
  log(std::format("Packed and stripped file {}.", dstfile.string()));
}

static auto pack_dir(const fs::path &srcdir, const fs::path &dstroot,
                     std::string_view dstname = "", bool symlink = false) {
  auto dstdir = dstroot / (dstname.size() ? dstname : srcdir.filename());
  if (!dstname.size() && fs::exists(dstdir))
    log_return(std::format("Ignored packing {}, {} exists.", srcdir.string(),
                           dstdir.string()),
               return false);
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
  return true;
}

static void pack_ios_ipa(const fs::path &projroot, const fs::path &outroot,
                         const fs::path &icpproot, std::string_view version) {
  auto xcodeproj = projroot / "ios/icpp-server/icpp-server.xcodeproj";
  auto buildout = projroot / "ios/icpp-server/build-ipa";

  std::println("Removing old build {}...", buildout.string());
  fs::remove_all(buildout);

  std::println("Building icpp-server...");
  std::system(
      std::format("xcodebuild -project {} -scheme icpp-server -configuration "
                  "Release CONFIGURATION_BUILD_DIR={} build",
                  xcodeproj.string(), buildout.string())
          .data());

  auto approot = buildout / "icpp-server.app";
  std::println("Packing runtime libraries....");
  pack_dir(icpproot / "lib", approot, "", true);
  pack_file(icpproot / "bin/icpp-gadget.dylib", approot / "lib", "strip");

  std::println("Codesigning mach-o files...");
  std::system(
      std::format("codesign --force --sign - {}/icpp-server", approot.string())
          .data());
  std::system(
      std::format("codesign --force --sign - {}/lib/*.dylib", approot.string())
          .data());

  auto payload = buildout / "Payload";
  std::println("Packing the final ipa file...");
  create_dir(payload);
  std::system(
      std::format("mv {} {}/", approot.string(), payload.string()).data());
  std::system(std::format("cd {}; find Payload -name .DS_Store -delete; zip -r "
                          "-9 icpp.ipa Payload/",
                          buildout.string())
                  .data());

  auto finalipa = outroot / std::format("icpp-gadget-ios-v{}.ipa", version);
  std::system(
      std::format("mv {}/icpp.ipa {}", buildout.string(), finalipa.string())
          .data());
  std::println("Created icpp package {}.", finalipa.string());
}

int main(int argc, char **argv) {
  if (argc == 1)
    log_return(
        std::format("Usage: {} /path/to/prefix [/path/to/strip].", argv[0]),
        return 0);
  std::string llvm_strip;
  std::string_view android_strip;
  if (argc == 3) {
    android_strip = argv[2];
    log(std::format("Using user specified strip tool {}.", android_strip));
  } else {
    auto ndkhome = std::getenv("NDK_HOME");
    if (ndkhome) {
      llvm_strip = std::string(ndkhome) +
                   "toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-strip";
      android_strip = llvm_strip;
      log(std::format("Using auto detected strip tool {}.", android_strip));
    } else {
      std::println("The NDK_HOME environment variable isn't set, android "
                   "package will be ignored.");
    }
  }

  auto projroot = fs::absolute(argv[0]).parent_path() / "..";
  // create the destination directory if necessary
  auto dstroot = fs::path(argv[1]);
  create_dir(dstroot);

  std::string_view aevmdirs[] = {"AetherVM_InstallDir_iOS",
                                 "AetherVM_InstallDir_AndroidA64",
                                 "AetherVM_InstallDir_AndroidX64"};
  std::string_view osnames[] = {"ios", "android", "android"};
  std::string_view archnames[] = {"arm64", "arm64-v8a", "x86_64"};
  std::string_view exts[] = {".dylib", ".so", ".so"};
  std::string_view strips[] = {"strip", android_strip, android_strip};
  for (size_t i = 0; i < std::size(osnames); i++) {
    auto os = osnames[i];
    if (os == "android" && android_strip.size() == 0)
      continue;
#if __WIN__ || __LINUX__
    if (os == "ios")
      continue;
#endif

    auto arch = archnames[i];
    auto ext = exts[i];
    auto strip = strips[i];
    if (!strip.size())
      continue;

    auto cxxlib = projroot / std::format("cmake/cxxconf/build-{}/lib", arch);
    if (!fs::exists(cxxlib)) {
      log(std::format("There's no {}.", cxxlib.string()));
      continue;
    }

    // create icpp package layout
    auto version = std::format("{}.{}.{}", icpp::version_major,
                               icpp::version_minor, icpp::version_patch);
    auto pkgdir = std::format("icpp-gadget-v{}-{}-{}", version, os, arch);
    auto icpproot = dstroot / pkgdir;
    if (os == "ios")
      icpproot = icpproot / "usr/local";
    auto bin = icpproot / "bin";
    auto lib = icpproot / "lib";
    create_dir(icpproot);
    create_dir(bin);
    create_dir(lib);

    // copy cxx files
    pack_dir(cxxlib / ".", lib, ".", true);
    std::system(std::format("{0} {1}/*.a {1}/*.json",
#if __WIN__
                            "del",
#else
                            "rm",
#endif
                            lib.string())
                    .data());

    // copy icpp files
    auto libgadget = std::string("icpp-gadget") + ext.data();
    auto gadget =
        projroot / std::format("cmake/icpp-gadget/build-{}.Release", arch);
    for (auto &name :
         {libgadget, std::string("imod"), std::string("icpp-server")}) {
      pack_file(gadget / name, bin, strip);
      if (os == "ios")
        std::system(std::format("ldid -S{}/config/entitlement.xml {}/{}",
                                projroot.string(), bin.string(), name)
                        .data());
    }

    // copy LLVM file
    pack_file(gadget / std::format("llvm/lib/libLLVM{}", ext.data()), lib,
              strip);

    auto aether_install = std::getenv(aevmdirs[i].data());
    if (aether_install) {
      // copy AetherVM files
      pack_file(fs::path(aether_install) /
                    (std::string("aebi/lib/libAetherBinary") + ext.data()),
                lib, strip);
      pack_file(fs::path(aether_install) /
                    (std::string("lib/libAetherDbg") + ext.data()),
                lib, strip);
      pack_file(fs::path(aether_install) /
                    (std::string("lib/libAetherVMICPP") + ext.data()),
                lib, strip);

      // copy remill's semantic bitcode files
      pack_dir(fs::path(aether_install) / "lib/bitcode", lib);
    }

    if (os == "ios") {
      auto debroot = (dstroot / pkgdir).string();
      auto debfile = debroot + ".deb";
      auto ctrlfile = debroot + "/DEBIAN/control";
      if (pack_dir(std::format("{}/config/DEBIAN", projroot.string()),
                   debroot)) {
        // set version
        std::ifstream inf(ctrlfile, std::ios::ate);
        std::vector<char> fbuf(static_cast<size_t>(inf.tellg()) + 1, 0);
        inf.seekg(0, std::ios::beg);
        inf.read(&fbuf[0], fbuf.size());
        inf.close();

        std::ofstream outf(ctrlfile);
        auto verflag = std::strstr(&fbuf[0], "x.x.x");
        outf.write(&fbuf[0], verflag - &fbuf[0]);
        outf.write(version.data(), version.size());
        outf.write(&verflag[5], std::strlen(&verflag[5]));
        outf.close();
      }

      std::system(
          std::format("find {} -name .DS_Store -delete; dpkg-deb -b {} {}",
                      debroot, debroot, debfile)
              .data());

      pack_ios_ipa(projroot, dstroot, icpproot, version);
      continue;
    }

    auto targz = pkgdir + ".tar.gz";
    log(std::format("Packing icpp release package {}...", targz));
#if __APPLE__
    std::system(std::format("find {} -name .DS_Store -delete", dstroot.string())
                    .data());
#endif
    std::system(
        std::format("cd {} && tar czf {} {}", dstroot.string(), targz, pkgdir)
            .data());
    log(std::format("Created icpp package {}.", targz));
  }

  std::puts("Done");
  return 0;
}
