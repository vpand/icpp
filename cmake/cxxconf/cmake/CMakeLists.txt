#
# This file is used to build the icpp libc/libc++ runtime library.
#

# cmake
cmake_minimum_required(VERSION 3.20)
project(icpp CXX C ASM)

set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)

# build the host architecture target only
if (DEFINED ANDROID_ABI AND ANDROID_ABI STREQUAL "x86_64")
    set(LLVM_TARGETS_TO_BUILD "X86" CACHE STRING "" FORCE)
else()
    set(LLVM_TARGETS_TO_BUILD "AArch64" CACHE STRING "" FORCE)
endif()

set(LLVM_ENABLE_RUNTIMES "libc;libunwind;libcxxabi;libcxx" CACHE STRING "" FORCE)
set(LIBCXX_ENABLE_STATIC OFF CACHE BOOL "" FORCE)
set(LIBCXX_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)

add_subdirectory(${CMAKE_SOURCE_DIR}/../../../third/llvm-project/libunwind
                 ${CMAKE_BINARY_DIR}/libunwind)
add_subdirectory(${CMAKE_SOURCE_DIR}/../../../third/llvm-project/libcxxabi
                 ${CMAKE_BINARY_DIR}/libcxxabi)
add_subdirectory(${CMAKE_SOURCE_DIR}/../../../third/llvm-project/libcxx
                 ${CMAKE_BINARY_DIR}/libcxx)
