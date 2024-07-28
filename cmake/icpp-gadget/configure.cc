/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include <icpp.hpp>
#include <icppex.hpp>

int main(int argc, const char *argv[]) {
  if (argc == 1) {
    icpp::prints("Usage: {} /path/to/toolchain.cmake [x86_64|arm64].\n",
                 argv[0]);
    return 0;
  }

  auto thisfile = fs::absolute(argv[0]);
  auto thisdir = thisfile.parent_path().string();
  for (auto &type : {"Debug"s, "Release"s}) {
    icpp::strings args;
    args.push_back(std::format("-DCMAKE_TOOLCHAIN_FILE={}", argv[1]));
    args.push_back(std::format("-DCMAKE_BUILD_TYPE={}", type));
    args.push_back("-G");
    args.push_back("Ninja");

    std::string arch{"arm64"};
    if (args[0].find("android") != std::string::npos) {
      args.push_back("-DANDROID_PLATFORM=25");
      arch = "arm64-v8a";
      if (argc >= 3)
        arch = argv[2];
      args.push_back(std::format("-DANDROID_ABI={}", arch));
    }
    else {
      args.push_back("-DPLATFORM=OS64");
    }

    args.push_back("-B");
    args.push_back(std::format("{}/build-{}.{}", thisdir, arch, type));
    args.push_back(thisdir);
    bp::child(bp::search_path("cmake"), args).wait();
  }
  std::puts("Done.");
  return 0;
}
