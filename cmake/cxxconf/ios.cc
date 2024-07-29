/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include <icpp.hpp>
#include <icppex.hpp>

int main(int argc, const char *argv[]) {
  auto thisfile = fs::absolute(argv[0]);
  auto thisdir = thisfile.parent_path().string();
  icpp::strings args;
  args.push_back(std::format(
      "-DCMAKE_TOOLCHAIN_FILE={}/../../third/ios-cmake/ios.toolchain.cmake",
      thisdir));
  args.push_back(std::format("-DCMAKE_BUILD_TYPE=Release"));
  args.push_back("-DLIBCXX_INCLUDE_BENCHMARKS=OFF");
  args.push_back("-G");
  args.push_back("Ninja");
  args.push_back("-DPLATFORM=OS64");
  args.push_back("-DDEPLOYMENT_TARGET=10.0");
  args.push_back("-B");
  args.push_back(std::format("{}/build-arm64", thisdir));
  args.push_back((fs::path(thisdir) / "cmake").string());
  bp::child(bp::search_path("cmake"), args).wait();

  std::puts("Done.");
  return 0;
}
