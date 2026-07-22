/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2026 */
/* Copyright (c) vpand.com 2026. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

/*
ICPP has upgraded LLVM from 19.0.0git to 22.1.8 since v0.3.0, use this
script to cmake icpp if you want to build your own version.

The reason is:
To reduce the package size of ICPP + AetherVM, we have to build LLVM as a shared
library, but too many linking issues occur after we turn LLVM_BUILD_LLVM_DYLIB
on for LLVM cmake, so this script will patch some llvm headers to fix those
errors.

The initial icpp package can be downloaded for your local system at:
  https://github.com/vpand/icpp/releases

Usage: icpp build.cc [build_dir]
*/

#include "runtime/include/icpp.hpp"

namespace {

bool patch_string(std::string_view infile, std::string_view patch_flag,
                  std::string_view pattern, std::string_view replace) {
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
    outf.write(patch_flag.data(), patch_flag.size());
    outf.write("\n", 1);
    outf.write(content.data(), content.size());
  }

  // rename the temp as the original file
  fs::rename(temp_file, infile);
  return true;
}

} // namespace

int main(int argc, const char *argv[]) {
  std::string_view build_dir = argc == 2 ? argv[1] : "build";
  std::string_view build_type = build_dir.contains("debug") ||
                                        build_dir.contains("Debug") ||
                                        build_dir.contains("dev")
                                    ? "Debug"
                                    : "Release";

  auto proj_root = fs::absolute(argv[0]).parent_path();
  auto build_root = argc == 2 ? fs::absolute(build_dir) : proj_root / build_dir;
  // stage 1: check whether need to initialize ninja build
  auto ninja_build = build_root / "build.ninja";
  if (!fs::exists(ninja_build)) {
#if __APPLE__
    auto cmake =
        std::format("cmake -G Ninja -S {} -B {} -DCMAKE_BUILD_TYPE={}",
                    proj_root.string(), build_root.string(), build_type);
#elif __LINUX__
    auto prebuilt_llvm_bin = proj_root.string() + "/build/llvm/bin";
    auto cmake =
        std::format("cmake -G Ninja -S {} -B {} -DCMAKE_BUILD_TYPE={} "
                    "-DCMAKE_C_COMPILER={}/clang -DCMAKE_CXX_COMPILER={}/clang",
                    proj_root.string(), build_root.string(), build_type,
                    prebuilt_llvm_bin, prebuilt_llvm_bin);
#else
    auto cmake =
        std::format("cmake -G Ninja -S {} -B {} -DCMAKE_BUILD_TYPE={} "
                    "-DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl",
                    proj_root.string(), build_root.string(), build_type);
#endif
    std::system(cmake.c_str());
    if (!fs::exists(ninja_build)) {
      std::println("Failed: {}", cmake);
      return -1;
    }
    // build protoc
    std::system(
        std::format("cmake --build {} -- protoc", build_root.string()).c_str());
  }
  // stage 2.1: patch targets which depend on libLLVM
  constexpr std::string_view ninja_patch_flag = "# ICPP Patched File";
  std::string firstline;
  std::getline(std::ifstream(ninja_build, std::ios::binary), firstline);
  if (!firstline.starts_with(ninja_patch_flag)) {
    std::println("Patching {}...", ninja_build.string());
#define llvm_libpre "third/llvm-project/llvm/lib/"
#define support_objpre llvm_libpre "Support/CMakeFiles/LLVMSupport.dir/"
#if __APPLE__
    patch_string(
        ninja_build.string(), ninja_patch_flag,
        ".a  " llvm_libpre "libLLVM.dylib",
        ".a " llvm_libpre "libLLVM.dylib " llvm_libpre
        "libLLVMDTLTO.a " support_objpre "SmallVector.cpp.o " support_objpre
        "Z3Solver.cpp.o " support_objpre
        "VirtualOutputBackends.cpp.o " support_objpre
        "VirtualOutputBackend.cpp.o " support_objpre
        "VirtualOutputError.cpp.o " support_objpre
        "VirtualOutputFile.cpp.o " support_objpre "raw_ostream_proxy.cpp.o ");
#elif __LINUX__
#else
#endif
  }
#if __WIN__ || __APPLE__ // linux has the right definition of LLVM_TEMPLATE_ABI
  // stage 2.2: patch Compiler.h to correct LLVM_TEMPLATE_ABI
  constexpr std::string_view hdr_patch_flag = "// ICPP Patched File";
  firstline.clear();
  auto hdr_compiler =
      (proj_root / "third/llvm-project/llvm/include/llvm/Support/Compiler.h")
          .string();
  std::getline(std::ifstream(hdr_compiler, std::ios::binary), firstline);
  if (!firstline.starts_with(hdr_patch_flag)) {
    std::println("Patching {}...", hdr_compiler);
    patch_string(hdr_compiler, hdr_patch_flag, "#if !defined(LLVM_ABI)",
                 R"(
#if defined(LLVM_EXPORTS)
#undef LLVM_TEMPLATE_ABI
#define LLVM_TEMPLATE_ABI LLVM_ABI
#endif                

#if !defined(LLVM_ABI))");
  }
#endif
  // stage 3: build with cmake and ninja
  std::system(
      std::format("cmake --build {} -- lld clang clang-repl clang-format icpp "
                  "icppcli imod iopad icpp-gadget icpp-server",
                  build_root.string())
          .c_str());
  // stage 4: recheck whether build.ninja updated
  firstline.clear();
  std::getline(std::ifstream(ninja_build, std::ios::binary), firstline);
  if (firstline.starts_with(ninja_patch_flag))
    return 0;
  std::println("Rebuilding as build.ninja updated...");
  return main(argc, argv);
}
