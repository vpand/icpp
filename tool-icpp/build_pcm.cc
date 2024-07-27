/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

/*
This is a C++ script to build the cppm in ICPP_ROOT/runtime/module into
a precompiled pcm file using the local system triple.

Usage: icpp build_pcm.cc

The initial icpp package can be downloaded for your local system at:
https://github.com/vpand/icpp/releases
*/

#include <cstdlib>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>

namespace fs = std::filesystem;

using namespace std::literals::string_literals;
using namespace std::literals::string_view_literals;

#if __aarch64__ || __arm64__
#define ARCH_ARM64 1
#else
#define ARCH_X64 1
#endif

#if ARCH_X64
constexpr auto archname = "x86_64"s;
#else
#if __APPLE__
constexpr auto archname = "arm64"s;
#else
constexpr auto archname = "aarch64"s;
#endif
#endif

#if __APPLE__
constexpr auto platname = "apple"sv;
constexpr auto vendername = "apple"s;
constexpr auto envname = "darwin19.0.0"s;
#elif __linux__
constexpr auto platname = "linux"sv;
constexpr auto vendername = "unknown-linux"s;
constexpr auto envname = "gnu"s;
#else
constexpr auto platname = "win"sv;
constexpr auto vendername = "pc-windows"s;
constexpr auto envname = "msvc19.0.0"s;
#endif

#if _WIN32
#define CLANG "clang-cl.exe"

constexpr auto ucrtinc = "runtime/win/ucrt"sv;
constexpr auto vcinc = "runtime/win/vc"sv;

constexpr std::string win_include(const fs::path &root) {
  return "-I"s + (root / ucrtinc).string() +
         " "
         "-I" +
         (root / vcinc).string();
}
#else
#define CLANG "clang"
#endif

constexpr auto cppinc = "runtime/include/c++/v1"sv;

constexpr auto stdcppm_dir = "runtime/module/libc++/v1"sv;
constexpr auto stdcppm = "std.cppm"sv;
constexpr auto compatcppm = "std.compat.cppm"sv;

#define log(fmt, ...) std::puts(std::format(fmt, __VA_ARGS__).data())

constexpr std::string triple() {
  return archname + "-" + vendername + "-" + envname;
}

constexpr std::string cpp_include(const fs::path &root) {
  return "-I"s + (root / cppinc).string();
}

constexpr std::string apple_sysroot(const fs::path &root) {
  return (root / "runtime/apple").string();
}

static void precompile(const fs::path &root, const fs::path &cppm) {
  auto cppmpath = root / stdcppm_dir / cppm;
  auto pcmroot = root / "runtime" / platname / "module";
  auto pcmpath = pcmroot / (cppm.stem().string() + ".pcm");

  std::string cmd =
      (root / "build/third/llvm-project/llvm/bin/" CLANG).string() +
      " -target " + triple() + " " + cpp_include(root) + " " +
      cppmpath.string() + " -o " + pcmpath.string() + " ";
#if _WIN32
  cmd += win_include(root) + " /clang:--precompile /clang:-std=c++23 "
                             "/clang:-nostdinc++ /clang:-nostdlib++ /MD /EHsc "
                             "/clang:";
#else
  cmd += "--precompile -std=c++23 -nostdinc++ -nostdlib++ ";
#if __APPLE__
  cmd += "-isysroot " + apple_sysroot(root) + " ";
#endif
#endif
  cmd += "-fprebuilt-module-path=" + pcmroot.string();

  log("Executing: {}", cmd);
  std::system(cmd.data());
}

int main(int argc, const char *argv[]) {
  auto thisfile = fs::absolute(argv[0]);
  log("Running {}...", thisfile.string());

  auto icpproot = thisfile.parent_path().parent_path();
  for (auto &cppm : {stdcppm, compatcppm})
    precompile(icpproot, cppm);

  log("{}", "Done.");
  return 0;
}
