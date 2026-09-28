# Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
# Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
# SPDX-License-Identifier: Apache License, Version 2.0
# See LICENSE file in the root directory for full license text.

#
# This file is used to build the icpp-gadget/icpp-server for Android and iOS.
#

# cmake
cmake_minimum_required(VERSION 3.20)

project(icpp CXX C)

if(APPLE)
  # LLVM needs this to set the correct linker flags
  set(CMAKE_SYSTEM_NAME "Darwin")
endif()

set(LIBCXX_LINKER_FLAGS "-L${LIBCXX_LIB_ROOT} -lc++.1 -lc++abi.1 -lunwind.1")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LIBCXX_LINKER_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LIBCXX_LINKER_FLAGS}")

# prebuilt binary engine
find_package(AetherBinary CONFIG REQUIRED)
find_package(AetherVM CONFIG REQUIRED)

# c++
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED)

set(ICPP_ROOT ${CMAKE_SOURCE_DIR}/../..)
set(ICPP_SRCROOT ${ICPP_ROOT}/src)

# build LLVM as shared library by default
set(LLVM_SHLIB ON)

# build all dependent libraries as static
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

# icpp only supports x86_64/arm64 currently, but we're building LLVM which can be 
# reused by AetherVM
set(LLVM_TARGETS_TO_BUILD "X86;ARM;AArch64;Sparc" CACHE STRING "" FORCE)

# llvm
message(STATUS "Configuring llvm for ${CMAKE_SYSTEM_NAME}...")
set(LLVM_INCLUDE_TOOLS ON CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_UTILS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_TESTS OFF CACHE BOOL "" FORCE)
set(LLVM_INCLUDE_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_ZLIB "OFF" CACHE STRING "" FORCE)
set(LLVM_ENABLE_ZSTD "OFF" CACHE STRING "" FORCE)
# build llvm as a shared library to massively reduce the final package size
set(LLVM_BUILD_LLVM_DYLIB ${LLVM_SHLIB} CACHE BOOL "" FORCE)
set(LLVM_LINK_LLVM_DYLIB ${LLVM_SHLIB} CACHE BOOL "" FORCE)
set(LLVM_ENABLE_PLUGINS OFF CACHE BOOL "" FORCE)
set(LLVM_ENABLE_EXPORTED_SYMBOLS_IN_PLUGINS OFF CACHE BOOL "" FORCE)
add_subdirectory(${ICPP_ROOT}/third/llvm-project/llvm
                 ${CMAKE_BINARY_DIR}/llvm)

#
# third-party projects
#

# boost
message(STATUS "Configuring boost...")
if (WIN32)
  set(BOOST_CONTEXT_IMPLEMENTATION winfib)
endif()
add_subdirectory(${ICPP_ROOT}/third/boost
                 ${CMAKE_BINARY_DIR}/boost)

# protobuf
message(STATUS "Configuring protobuf...")
set(protobuf_WITH_ZLIB OFF CACHE BOOL "" FORCE)
add_subdirectory(${ICPP_ROOT}/third/protobuf
                 ${CMAKE_BINARY_DIR}/protobuf)

# brotli
message(STATUS "Configuring brotli...")
add_subdirectory(${ICPP_ROOT}/third/brotli
                 ${CMAKE_BINARY_DIR}/brotli)

#
# icpp projects
#

if(APPLE)
  add_link_options(-Wl,-rpath,@executable_path 
                   -Wl,-rpath,@executable_path/../lib
                   -Wl,-rpath,@loader_path
                   -Wl,-rpath,@loader_path/../lib)
endif()

set(DISABLE_RTTI -fno-rtti)
set(THIRD_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../third)
set(LLVMLIB_DIR ${CMAKE_BINARY_DIR}/llvm/lib)
set(LLVMSupport_DIR ${LLVMLIB_DIR}/Support/CMakeFiles/LLVMSupport.dir)
set(LLVM_INCLUDE_ROOT ${THIRD_ROOT}/llvm-project/llvm/include)
set(LLVM_MINIMAL_LIBS LLVM)

# generate the protocol sources with protoc
add_custom_command(
  OUTPUT 
    icppdbg.pb.cc icppiobj.pb.cc isymhash.pb.cc 
    icppmod.pb.cc
    icpppad.pb.cc
  COMMAND ${ICPP_ROOT}/build/third/protobuf/protoc  
    -I=${ICPP_ROOT}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${ICPP_ROOT}/proto/icppdbg.proto
  COMMAND ${ICPP_ROOT}/build/third/protobuf/protoc  
    -I=${ICPP_ROOT}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${ICPP_ROOT}/proto/icppiobj.proto
  COMMAND ${ICPP_ROOT}/build/third/protobuf/protoc  
    -I=${ICPP_ROOT}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${ICPP_ROOT}/proto/isymhash.proto
  COMMAND ${ICPP_ROOT}/build/third/protobuf/protoc  
    -I=${ICPP_ROOT}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${ICPP_ROOT}/proto/icppmod.proto
  COMMAND ${ICPP_ROOT}/build/third/protobuf/protoc  
    -I=${ICPP_ROOT}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${ICPP_ROOT}/proto/icpppad.proto
  DEPENDS ${ICPP_ROOT}/proto/icppdbg.proto
          ${ICPP_ROOT}/proto/icppiobj.proto
          ${ICPP_ROOT}/proto/isymhash.proto
          ${ICPP_ROOT}/proto/icppmod.proto
          ${ICPP_ROOT}/proto/icpppad.proto
  VERBATIM)

file(GLOB ICPP_CORE_SOURCES
  ${ICPP_SRCROOT}/arch.cpp
  ${ICPP_SRCROOT}/exec.cpp
  ${ICPP_SRCROOT}/icpp.cpp
  ${ICPP_SRCROOT}/loader.cpp
  ${ICPP_SRCROOT}/log.cpp
  ${ICPP_SRCROOT}/platform.cpp
  ${ICPP_SRCROOT}/runcfg.cpp
  ${ICPP_SRCROOT}/runtime.cpp
  ${ICPP_SRCROOT}/utils.cpp
)

# icpp module manager command line
message(STATUS "Configuring icpp module manager imod...")

file(GLOB IMOD_LLVM_SOURCES
  ${ICPP_SRCROOT}/icpp-mod.cpp
  ${ICPP_SRCROOT}/object.cpp
  ${ICPP_SRCROOT}/object-coff.cpp
)

add_executable(imod 
  ${IMOD_LLVM_SOURCES}
  ${ICPP_SRCROOT}/arch.cpp
  ${ICPP_SRCROOT}/icpp.cpp
  ${ICPP_SRCROOT}/loader.cpp
  ${ICPP_SRCROOT}/log.cpp
  ${ICPP_SRCROOT}/platform.cpp
  ${ICPP_SRCROOT}/runcfg.cpp
  ${ICPP_SRCROOT}/runtime.cpp
  ${ICPP_SRCROOT}/utils.cpp
  ${ICPP_SRCROOT}/imod/createcfg.cpp
  isymhash.pb.cc
  icppmod.pb.cc
  icppiobj.pb.cc
)
set_source_files_properties(${IMOD_LLVM_SOURCES} PROPERTIES COMPILE_FLAGS ${DISABLE_RTTI})
target_include_directories(imod PRIVATE
  ${LLVM_INCLUDE_ROOT}
  ${CMAKE_BINARY_DIR}/llvm/include
  ${THIRD_ROOT}/brotli/c/include
  ${CMAKE_CURRENT_BINARY_DIR}
  ${THIRD_ROOT}/protobuf/third_party/utf8_range
)
target_link_libraries(imod PRIVATE
  AetherBinary::AetherBinary

  ${LLVM_MINIMAL_LIBS}

  boost_asio
  boost_beast
  boost_json
  boost_process
  brotlicommon
  brotlienc
  brotlidec
  libprotobuf
)

# icpp gadget, running as a daemon in somewhere to receive the
# interpretable object to execute
message(STATUS "Configuring memory resident interpreter icpp-gadget...")

file(GLOB IGADGET_LLVM_SOURCES
  ${ICPP_SRCROOT}/icpp-gadget.cpp
  ${ICPP_SRCROOT}/object.cpp
  ${ICPP_SRCROOT}/object-coff.cpp
  ${ICPP_SRCROOT}/object-llvm.cpp
)

add_library(icpp-gadget SHARED 
  ${ICPP_CORE_SOURCES}

  # llvm relational files
  ${IGADGET_LLVM_SOURCES}

  # auto generated by protoc
  icppdbg.pb.cc
  icppiobj.pb.cc
  isymhash.pb.cc
  icpppad.pb.cc
)
set_target_properties(icpp-gadget PROPERTIES PREFIX "")
target_compile_definitions(icpp-gadget PRIVATE ICPP_DLLIMPL=1)
set_source_files_properties(${IGADGET_LLVM_SOURCES} PROPERTIES COMPILE_FLAGS ${DISABLE_RTTI})
target_include_directories(icpp-gadget PRIVATE 
  ${LLVM_INCLUDE_ROOT}
  ${CMAKE_BINARY_DIR}/llvm/include
  ${CMAKE_CURRENT_BINARY_DIR}
  ${LLVM_OBJDUMP_ROOT}
  ${THIRD_ROOT}/protobuf/third_party/utf8_range
)
target_link_libraries(icpp-gadget PRIVATE 
  AetherBinary::AetherBinary
  AetherVM::AetherVM

  ${LLVM_MINIMAL_LIBS}

  boost_asio
  boost_beast
  boost_json
  libprotobuf
)
if(APPLE)
  target_link_options(icpp-gadget PRIVATE -Wl,-exported_symbol -Wl,_icpp_gadget)
endif()

# icpp-server command line
message(STATUS "Configuring icpp-server remote daemon...")
add_executable(icpp-server ${ICPP_SRCROOT}/icpp-server.cpp)
target_include_directories(icpp-server PRIVATE 
  ${CMAKE_BINARY_DIR}/llvm/include
  boost_dll
)
target_link_libraries(icpp-server PRIVATE boost_dll)

message(STATUS "Configuring icpp done")
