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

std::string aethervm_installdir_ios() {
  constexpr const char *env = "AetherVM_InstallDir_iOS";
  auto var = std::getenv(env);
  if (var)
    return var;

  std::println("Please set the {} environment variable. You can build it from "
               "the source code https://github.com/AetherVM/AetherVM with "
               "\"icpp ios/build.cc\".",
               env);
  return "";
}

std::string aethervm_installdir_android() {
  constexpr const char *env = "AetherVM_InstallDir_Android";
  auto var = std::getenv(env);
  if (var)
    return var;

  std::println("Please set the {} environment variable. You can build it from "
               "the source code https://github.com/AetherVM/AetherVM with "
               "\"icpp android/build.cc\".",
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

    auto aethervm_dir =
        ios ? aethervm_installdir_ios() : aethervm_installdir_android();
    if (!aethervm_dir.size())
      return -1;

    std::string cxxlibs;
    icpp::strings args;
    args.push_back(std::format("-DCMAKE_TOOLCHAIN_FILE={}", toolchain));
    args.push_back(std::format("-DCMAKE_CROSSCOMPILING=TRUE"));
    args.push_back(std::format("-DCMAKE_BUILD_TYPE={}", type));
    args.push_back(std::format("-DLLVM_TABLEGEN={}/../../build/third/"
                               "llvm-project/llvm/bin/llvm-tblgen",
                               thisdir));
    args.push_back("-G");
    args.push_back("Ninja");

    std::string arch{"arm64"};
    if (args[0].find("android") != std::string::npos) {
      args.push_back("-DANDROID_PLATFORM=25");
      arch = "arm64-v8a";
      if (argc >= 3)
        arch = argv[2];
      args.push_back(std::format("-DANDROID_ABI={}", arch));
      args.push_back(
          std::format("-DCMAKE_CXX_FLAGS=-nostdinc++ -nostdlib++ -fPIC "
                      "-I{}/../../runtime/include/c++/v1",
                      thisdir));
      cxxlibs =
          std::format("-L{}/../cxxconf/build-{}/lib -lc++ -lc++abi -lunwind",
                      thisdir, arch);
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
      cxxlibs = std::format("-L{}/../cxxconf/build-{}/lib -lc++.1 -lc++abi.1 "
                            "-lunwind.1 -framework Foundation",
                            thisdir, arch);
    }
    args.push_back(std::format("-DCMAKE_SHARED_LINKER_FLAGS=\"{}\"", cxxlibs));
    args.push_back(std::format("-DCMAKE_EXE_LINKER_FLAGS=\"{}\"", cxxlibs));
    args.push_back(
        std::format("-DCMAKE_PREFIX_PATH=\"{0};{0}/aebi\"", aethervm_dir));

    args.push_back("-Wno-deprecated");
    args.push_back("-B");
    args.push_back(std::format("{}/build-{}.{}", thisdir, arch, type));
    args.push_back(thisdir);
    command("cmake", args);
  }
  std::puts("Done.");
  return 0;
}
