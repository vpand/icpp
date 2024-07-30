/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include <icpp.hpp>
#include <icppex.hpp>

int main(int argc, const char *argv[]) {
  if (argc == 1) {
    icpp::prints("Usage: {} /path/to/toolchain.cmake [x86_64].\n", argv[0]);
    return 0;
  }

  auto thisfile = fs::absolute(argv[0]);
  auto thisdir = thisfile.parent_path();
  icpp::strings args;
  args.push_back(std::format("-DCMAKE_TOOLCHAIN_FILE={}", argv[1]));
  args.push_back(std::format("-DCMAKE_BUILD_TYPE=Release"));
  args.push_back("-DBUILD_SHARED_LIBS=ON");
  args.push_back("-DBOOST_IOSTREAMS_ENABLE_LZMA=OFF");
  args.push_back("-G");
  args.push_back("Ninja");
  args.push_back(std::format("-DCMAKE_CXX_FLAGS=-nostdinc++ -nostdlib++ -fPIC "
                             "-I{}/../../runtime/include/c++/v1",
                             thisdir.string()));

  std::string arch{"arm64"};
  if (args[0].find("android") != std::string::npos) {
    args.push_back("-DANDROID_PLATFORM=25");
    arch = "arm64-v8a";
    if (argc >= 3)
      arch = argv[2];
    args.push_back(std::format("-DANDROID_ABI={}", arch));
    args.push_back(
        std::format("-DCMAKE_SHARED_LINKER_FLAGS=-L{}/../cxxconf/"
                    "build-{}/lib -lc++ -lc++abi -lunwind @{}/../../src/ld.txt",
                    thisdir.string(), arch, thisdir.string()));
  } else {
    args.push_back("-DPLATFORM=OS64");
    args.push_back("-DDEPLOYMENT_TARGET=10.0");
    args.push_back(std::format("-DCMAKE_SHARED_LINKER_FLAGS=-L{}/../cxxconf/"
                               "build-{}/lib -lc++.1 -lc++abi.1 -lunwind.1",
                               thisdir.string(), arch));
  }

  args.push_back("-B");
  args.push_back(std::format("{}/build-{}", thisdir.string(), arch));
  args.push_back((thisdir / "../../third/boost").string());
  bp::child(bp::search_path("cmake"), args).wait();

  std::puts("Done.");
  return 0;
}
