#
# This file is used to build the icpp libc/libc++ runtime library.
#

# cmake
cmake_minimum_required(VERSION 3.20)
project(icpp)

if(NOT CMAKE_CXX_COMPILER)
if(WIN32)
set(compiler clang-cl)
else()
set(compiler clang)
endif()

find_program(compiler_path ${compiler})
if(NOT compiler_path)
  message(FATAL_ERROR "Compiler '${compiler}' not found, make sure it's in your system PATH.")
else()
  message(STATUS "Found compiler '${compiler}' at '${compiler_path}'.")
endif()

set(CMAKE_C_COMPILER ${compiler_path} CACHE STRING "" FORCE)
set(CMAKE_CXX_COMPILER ${compiler_path} CACHE STRING "" FORCE)
endif()

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(ICPPCLANG ${CMAKE_BINARY_DIR}/../llvm)
  set(ICXXINCLUDE ${ICPPCLANG}/include)
  set(ICXXLIB ${ICPPCLANG}/lib/${CMAKE_HOST_SYSTEM_PROCESSOR}-unknown-linux-gnu)
  # apply our custom built libc++ compile/link flags
  add_compile_options(-nostdinc++ -nostdlib++ -fPIC -I${ICXXINCLUDE}/c++/v1 
    -I${ICXXINCLUDE}/${CMAKE_HOST_SYSTEM_PROCESSOR}-unknown-linux-gnu/c++/v1)
  add_link_options(-L${ICXXLIB} -Wl,-rpath,${ICXXLIB} -lc -lm -lc++)
  # as we're already using the latest clang, any further checks are redundant
  set(LLVM_COMPILER_CHECKED TRUE)
  # set this variable to disable llvm's cmake to do any more checks, it's really annoying...
  set(LLVM_COMPILER_IS_GCC_COMPATIBLE FALSE)
endif()

set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)

# build the host architecture target only
if (${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64" OR
    ${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "AMD64")
    set(LLVM_TARGETS_TO_BUILD "X86" CACHE STRING "" FORCE)
else()
    set(LLVM_TARGETS_TO_BUILD "AArch64" CACHE STRING "" FORCE)
endif()

# enable libc/libcxx for C/C++ runtime library
if (WIN32)
  set(LLVM_ENABLE_RUNTIMES "libcxx" CACHE STRING "" FORCE)
else()
  set(LLVM_ENABLE_PROJECTS "libc" CACHE STRING "" FORCE)
  set(LLVM_ENABLE_RUNTIMES "libc;libunwind;libcxxabi;libcxx" CACHE STRING "" FORCE)
endif()

set(LLVM_INCLUDE_RUNTIMES ON CACHE BOOL "" FORCE)
set(LLVM_LIBC_FULL_BUILD ON CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_UTILS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_TESTS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_ZLIB "OFF" CACHE STRING "" FORCE)
set(LLVM_ENABLE_ZSTD "OFF" CACHE STRING "" FORCE)
set(LIBC_ENABLE_UNITTESTS OFF CACHE BOOL "" FORCE)
set(LIBC_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LIBCXX_ENABLE_STATIC OFF CACHE BOOL "" FORCE)
set(LIBCXX_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../third/llvm-project/llvm
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../build/libcxx)
