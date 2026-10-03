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

} // namespace

int main(int argc, const char *argv[]) {
  if (argc == 1) {
    std::println("Usage: {} /path/to/toolchain.cmake [x86_64].\n", argv[0]);
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
#if __WIN__
  args.push_back("-DPython3_EXECUTABLE=python");
#endif

  std::string arch{"arm64"};
  args.push_back("-DANDROID_PLATFORM=25");
  arch = "arm64-v8a";
  if (argc >= 3)
    arch = argv[2];
  args.push_back(std::format("-DANDROID_ABI={}", arch));

  args.push_back("-Wno-deprecated");
  args.push_back("-B");
  args.push_back(std::format("{}/build-{}", thisdir, arch));
  args.push_back((fs::path(thisdir) / "cmake").string());
  command("cmake", args);

  std::puts("Done.");
  return 0;
}
