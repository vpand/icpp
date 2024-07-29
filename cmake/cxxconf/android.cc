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
  icpp::strings args;
  args.push_back(std::format("-DCMAKE_TOOLCHAIN_FILE={}", argv[1]));
  args.push_back(std::format("-DCMAKE_BUILD_TYPE=Release"));
  args.push_back("-DLIBCXX_INCLUDE_BENCHMARKS=OFF");
  args.push_back("-G");
  args.push_back("Ninja");

  std::string arch{"arm64"};
  args.push_back("-DANDROID_PLATFORM=25");
  arch = "arm64-v8a";
  if (argc >= 3)
    arch = argv[2];
  args.push_back(std::format("-DANDROID_ABI={}", arch));

  args.push_back("-B");
  args.push_back(std::format("{}/build-{}", thisdir, arch));
  args.push_back((fs::path(thisdir) / "android").string());
  bp::child(bp::search_path("cmake"), args).wait();

  std::puts("Done.");
  return 0;
}
