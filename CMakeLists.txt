# cmake
cmake_minimum_required(VERSION 3.20)
project(icpp)

# workaround to fix wrong compiler on macOS
if(APPLE)
  set(CMAKE_C_COMPILER "/usr/bin/clang" CACHE FILEPATH "" FORCE)
endif()

# build all dependent libraries as static
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

# third-party project
# unicorn
message(STATUS "Configuring unicorn...")
# patch qemu mmu to enable the emulated code to access memory directly
execute_process(COMMAND python3
  ${CMAKE_CURRENT_SOURCE_DIR}/tool/qemu_mmu_patcher.py
  ${CMAKE_CURRENT_SOURCE_DIR}/third/unicorn/qemu/accel/tcg/cputlb.c)
# icpp only supports x86_64/arm64 currently
set(UNICORN_ARCH "x86;aarch64" CACHE STRING "" FORCE)
add_subdirectory(third/unicorn)

# clang
message(STATUS "Configuring llvm/clang...")
# patch llvm cmake to link icpp as a shared library, 
# it'll be much easier to integrate icpp to other native plugin system because of this
execute_process(COMMAND python3
${CMAKE_CURRENT_SOURCE_DIR}/tool/llvm_cmake_patcher.py
${CMAKE_CURRENT_SOURCE_DIR}/third/llvm-project/llvm/cmake/modules/AddLLVM.cmake)
# icpp only supports x86_64/arm64 currently
set(LLVM_TARGETS_TO_BUILD "X86;AArch64" CACHE STRING "" FORCE)
set(LLVM_ENABLE_PROJECTS "clang" CACHE STRING "" FORCE)
set(LLVM_INCLUDE_UTILS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_RUNTIMES OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_TESTS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_ZLIB "OFF" CACHE STRING "" FORCE)
set(LLVM_ENABLE_ZSTD "OFF" CACHE STRING "" FORCE)
add_subdirectory(third/llvm-project/llvm)

# protobuf
message(STATUS "Configuring protobuf...")
add_subdirectory(third/protobuf)

# boost
message(STATUS "Configuring boost...")
add_subdirectory(third/boost)

# brotli
message(STATUS "Configuring brotli...")
add_subdirectory(third/brotli)

# icpp project
add_subdirectory(vmpstudio)
add_subdirectory(src)
