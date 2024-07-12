#
# This file is used to build the icpp libc/libc++ runtime library.
#

# cmake
cmake_minimum_required(VERSION 3.20)
project(icpp)

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

set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
set(CMAKE_C_COMPILER ${compiler_path} CACHE STRING "" FORCE)
set(CMAKE_CXX_COMPILER ${compiler_path} CACHE STRING "" FORCE)
set(LIBCXX_ENABLE_STATIC OFF CACHE BOOL "" FORCE)
set(LIBCXX_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)
if (UNIX)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../third/llvm-project/libc
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../build/libc)
endif()
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../../third/llvm-project/libcxx
                 ${CMAKE_CURRENT_SOURCE_DIR}/../../build/libcxx)
