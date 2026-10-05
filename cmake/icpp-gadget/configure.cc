// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include <icpp.hpp>

namespace {

bool command(std::string_view proc, const icpp::strings &args) {
  std::string cmd{proc};
  for (auto &a : args)
    cmd += " " + a;

  std::println("{}", cmd);
#if 1
  return std::system(cmd.data()) == 0;
#else
  return true;
#endif
}

bool patch_string(std::string_view infile, std::string_view pattern,
                  std::string_view replace) {
  std::stringstream buffer;
  {
    // read file
    buffer << std::ifstream(fs::path(infile), std::ios::in | std::ios::binary)
                  .rdbuf();
  }

  std::string content = buffer.str();
  std::size_t pos = 0;
  while ((pos = content.find(pattern, pos)) != std::string::npos) {
    // do the replacement
    content.replace(pos, pattern.length(), replace);
    pos += replace.length();
  }

  fs::path temp_file = infile;
  temp_file.replace_extension(".tmp");
  {
    // write file
    std::ofstream outf(temp_file,
                       std::ios::out | std::ios::binary | std::ios::trunc);
    outf.write(content.data(), content.size());
  }

  // rename the temp as the original file
  fs::rename(temp_file, infile);
  std::println("Patched {} for '{}' with '{}'.", infile, pattern, replace);
  return true;
}

std::string aethervm_installdir_ios() {
  constexpr const char *env = "AetherVM_InstallDir_iOS";
  auto var = std::getenv(env);
  if (var)
    return var;

  std::println("Please set the {} environment variable. You can build it from "
               "the source code https://github.com/AetherVM/AetherVM with "
               "\"icpp ios/build-icpp.cc\".",
               env);
  return "";
}

std::string aethervm_installdir_android(std::string_view arch) {
  auto env = arch.contains("arm") ? "AetherVM_InstallDir_AndroidA64"
                                  : "AetherVM_InstallDir_AndroidX64";
  auto var = std::getenv(env);
  if (var)
    return var;

  std::println("Please set the {} environment variable. You can build it from "
               "the source code https://github.com/AetherVM/AetherVM with "
               "\"icpp android/build-icpp.cc\".",
               env);
  return "";
}

} // namespace

int main(int argc, const char *argv[]) {
  if (argc == 1) {
    std::println("Usage: {} [/path/to/toolchain.cmake|android|ios] [x86_64].",
                 argv[0]);
    return 0;
  }

  auto thisfile = fs::absolute(argv[0]);
  auto thisdir = thisfile.parent_path().string();
  for (auto &type : {"Debug"s, "Release"s}) {
    std::string toolchain;
    bool ios = true;
    if (argv[1] == "android"sv) {
      ios = false;

      auto ndkhome = std::getenv("NDK_HOME");
      if (!ndkhome) {
        std::println("Please set the NDK_HOME environment variable.");
        return -1;
      }
      auto ndk_root = fs::path(ndkhome);
      if (fs::exists(ndk_root)) {
        toolchain = (ndk_root / "build/cmake/android.toolchain.cmake").string();
      } else {
        std::println("Invalid path {}.", ndkhome);
        return -1;
      }
    } else if (argv[1] == "ios"sv) {
      toolchain =
          (fs::path(thisdir) / "../../third/ios-cmake/ios.toolchain.cmake")
              .string();
    }

    icpp::strings args;
    args.push_back(std::format("-DCMAKE_TOOLCHAIN_FILE={}", toolchain));
    args.push_back(std::format("-DCMAKE_CROSSCOMPILING=TRUE"));
    args.push_back(std::format("-DCMAKE_BUILD_TYPE={}", type));
    args.push_back("-G");
    args.push_back("Ninja");

    std::string arch{"arm64"};
    if (args[0].find("android") != std::string::npos) {
      args.push_back("-DANDROID_PLATFORM=25");
      arch = "arm64-v8a";
      if (argc >= 3)
        arch = argv[2];
      std::string_view target = arch == "arm64-v8a" ? "aarch64-linux-android24"
                                                    : "x86_64-linux-android24";
      args.push_back(std::format("-DANDROID_ABI={}", arch));
      args.push_back(std::format("-DCMAKE_C_FLAGS=\"--target={}\"", target));
      args.push_back(std::format(
          "-DCMAKE_CXX_FLAGS=\"--target={} -nostdinc++ -nostdlib++ -fPIC "
          "-I{}/../../runtime/include/c++/v1\"",
          target, thisdir));
    } else {
      args.push_back("-DCMAKE_MACOSX_BUNDLE=NO");
      args.push_back("-DPLATFORM=OS64");
      args.push_back("-DDEPLOYMENT_TARGET=16.5");
      args.push_back(std::format(
          "-DCMAKE_CXX_FLAGS=\"-nostdinc++ -nostdlib++ -fPIC "
          "-I{}/../../runtime/include/c++/v1 "
          "-isysroot /Applications/Xcode.app/Contents/Developer/Platforms/"
          "iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk -DICPP_IOS=1\"",
          thisdir, thisdir));
    }
    auto aethervm_dir =
        ios ? aethervm_installdir_ios() : aethervm_installdir_android(arch);
    if (!aethervm_dir.size())
      return -1;

    std::string llvm_dir =
        aethervm_dir +
        std::format("/../../../../AetherBinary/build-{}-llvm/install",
                    ios ? "ios" : (std::format("android-") + arch));
    args.push_back(std::format("-DLIBCXX_LIB_ROOT={}/../cxxconf/build-{}/lib",
                               thisdir, arch));
    args.push_back(std::format("-DCMAKE_PREFIX_PATH=\"{0};{0}/aebi;{1}\"",
                               aethervm_dir, llvm_dir));
    args.push_back(std::format("-DLLVM_BUILD_DIR={}/../llvm", llvm_dir));
    args.push_back(std::format("-DLLVM_DIR={}/lib/cmake/llvm", llvm_dir));
    args.push_back(std::format(
        "-DAetherBinary_DIR={}/aebi/lib/cmake/AetherBinary", aethervm_dir));
    args.push_back(
        std::format("-DAetherVM_DIR={}/lib/cmake/AetherVM", aethervm_dir));

    auto builddir = std::format("{}/build-{}.{}", thisdir, arch, type);
    args.push_back("-Wno-deprecated");
    args.push_back("-B");
    args.push_back(builddir);
    args.push_back(thisdir);
    if (!command("cmake", args)) {
      std::println("Failed to configure the build.");
      return -1;
    }
#if __WIN__
    auto dst = fs::path(builddir + "/llvm");
    auto src = fs::path(llvm_dir);
    dst.make_preferred();
    src.make_preferred();
    command("mklink", {"/D", dst.string(), src.string()});
#else
    command("ln", {"-sf", llvm_dir, builddir + "/llvm"});
#endif

    if (ios) {
      // iPhoneSDK doesn't provide this library
      patch_string(builddir + "/build.ninja", "-lrt", " ");
    }
  }
  std::puts("Done.");
  return 0;
}
