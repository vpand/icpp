#
# This file is only used on Linux host to build a clang with libc++ support.
#

# cmake
cmake_minimum_required(VERSION 3.20)
project(icpp)

# build the host architecture target only
if (${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
set(LLVM_TARGETS_TO_BUILD "X86")
else()
set(LLVM_TARGETS_TO_BUILD "AArch64")
endif()

# enable clang
set(LLVM_ENABLE_PROJECTS "clang" CACHE STRING "" FORCE)

# enable cxx,cxxabi,unbind C++ runtime library
set(LLVM_ENABLE_RUNTIMES "all" CACHE STRING "" FORCE)
set(LLVM_INCLUDE_RUNTIMES ON CACHE BOOL "" FORCE)

set(LLVM_INCLUDE_UTILS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_TESTS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_ZLIB "OFF" CACHE STRING "" FORCE)
set(LLVM_ENABLE_ZSTD "OFF" CACHE STRING "" FORCE)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../third/llvm-project/llvm
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../build/llvm)
