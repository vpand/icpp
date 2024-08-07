/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include <icpp.hpp>
#include <icppex.hpp>

int main(int argc, const char *argv[]) {
  if (argc == 1) {
    icpp::prints("Usage: {} [/path/to/toolchain.cmake|android|ios] [x86_64].\n",
                 argv[0]);
    return 0;
  }

  auto thisfile = fs::absolute(argv[0]);
  auto thisdir = thisfile.parent_path().string();
  for (auto &type : {"Debug"s, "Release"s}) {
    std::string toolchain;
    if (argv[1] == "android"sv) {
      auto ndkbuild = bp::search_path("ndk-build");
      if (fs::exists(ndkbuild.string())) {
        toolchain =
            (ndkbuild.parent_path() / "build/cmake/android.toolchain.cmake")
                .string();
        argv[1] = toolchain.data();
      }
    }
    if (argv[1] == "ios"sv) {
      toolchain =
          (fs::path(thisdir) / "../../third/ios-cmake/ios.toolchain.cmake")
              .string();
      argv[1] = toolchain.data();
    }

    std::string cxxlibs;
    icpp::strings args;
    args.push_back(std::format("-DCMAKE_TOOLCHAIN_FILE={}", argv[1]));
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
      args.push_back("-DDEPLOYMENT_TARGET=10.0");
      args.push_back(std::format("-DCMAKE_C_FLAGS=-Dmmap=icpp_gadget_mmap "
                                 "-Dmunmap=icpp_gadget_munmap "
                                 "-DUNICORN_TRACER=1 "
                                 "-Dtrace_start=icpp_trace_start "
                                 "-Dtrace_end=icpp_trace_end",
                                 thisdir, thisdir));
      args.push_back(
          std::format("-DCMAKE_CXX_FLAGS=-nostdinc++ -nostdlib++ -fPIC "
                      "-I{}/../../runtime/include/c++/v1 "
                      "-isysroot {}/../../runtime/apple "
                      "-F/Applications/Xcode.app/Contents/Developer/Platforms/"
                      "iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/"
                      "Library/Frameworks -DICPP_IOS=1",
                      thisdir, thisdir));
      cxxlibs = std::format(
          "-L{}/../cxxconf/build-{}/lib -lc++.1 -lc++abi.1 -lunwind.1 "
          "-L/Applications/Xcode.app/Contents/Developer/Platforms/"
          "iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/lib "
          "-F/Applications/Xcode.app/Contents/Developer/Platforms/"
          "iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/System/Library/"
          "Frameworks -framework Foundation",
          thisdir, arch);
    }
    args.push_back(std::format("-DCMAKE_SHARED_LINKER_FLAGS={}", cxxlibs));
    args.push_back(std::format("-DCMAKE_EXE_LINKER_FLAGS={}", cxxlibs));

    args.push_back("-B");
    args.push_back(std::format("{}/build-{}.{}", thisdir, arch, type));
    args.push_back(thisdir);
    bp::child(bp::search_path("cmake"), args).wait();
  }
  std::puts("Done.");
  return 0;
}
