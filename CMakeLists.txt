# cmake
cmake_minimum_required(VERSION 3.20)
project(icpp)

# workaround to fix wrong compiler on macOS
if(APPLE)
  set(CMAKE_C_COMPILER "/usr/bin/clang" CACHE FILEPATH "" FORCE)
endif()

# workaround to process the different python/build command line name
if(MSVC)
  # python3 on Windows should be invoked as python
  set(PYTHON python)
  set(BUILDCMD ninja)
  # use the MultiThreadedDLL dynamical runtime mode for compiling and linking
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDebugDLL")
  else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
  endif()
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MD")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MDd")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MD")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MDd")
else()
  set(PYTHON python3)
  set(BUILDCMD make)
endif()

# check the dependent commands whether in system PATH
set(BUILDTOOLS ${PYTHON} ${BUILDCMD})
foreach(tool IN LISTS BUILDTOOLS)
  find_program(toolpath ${tool})
  if(NOT toolpath)
    message(FATAL_ERROR "Dependent tool '${tool}' not found, make sure it's in your system PATH.")
  else()
    message(STATUS "Found dependent tool '${tool}' at '${toolpath}'.")
    unset(toolpath CACHE)
  endif()
endforeach()

# build all dependent libraries as static
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

#
# third-party projects
#

# clang
message(STATUS "Configuring llvm/clang...")
# patch llvm cmake to link icpp as a shared library, 
# it'll be much easier to integrate icpp to other native plugin system because of this
execute_process(COMMAND ${PYTHON}
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
if(MSVC)
  # fix the Support/BLAKE3/CMakeLists.txt assembler error when building llvm with ninja
  set(LLVM_DISABLE_ASSEMBLY_FILES TRUE)
  
  # remove all the non ascii characters to make cl.exe working
  execute_process(COMMAND ${PYTHON}
    ${CMAKE_CURRENT_SOURCE_DIR}/tool/llvm_unicode_patcher.py
    ${CMAKE_CURRENT_SOURCE_DIR}/third/llvm-project/clang/lib/Lex/UnicodeCharSets.h)
endif()
add_subdirectory(third/llvm-project/llvm)

# protobuf
message(STATUS "Configuring protobuf...")
if(MSVC)
  # patch abseil random cmake to cmake correctly on Windows, otherwise it fails to cmake
  execute_process(COMMAND ${PYTHON}
    ${CMAKE_CURRENT_SOURCE_DIR}/tool/abseil_cmake_patcher.py
    ${CMAKE_CURRENT_SOURCE_DIR}/third/protobuf/third_party/abseil-cpp/absl/random/CMakeLists.txt)
endif()
add_subdirectory(third/protobuf)

# brotli
message(STATUS "Configuring brotli...")
add_subdirectory(third/brotli)

# boost
message(STATUS "Configuring boost...")
add_subdirectory(third/boost)

# unicorn
message(STATUS "Configuring unicorn...")
# patch qemu mmu to enable the emulated code to access memory directly
execute_process(COMMAND ${PYTHON}
  ${CMAKE_CURRENT_SOURCE_DIR}/tool/qemu_mmu_patcher.py
  ${CMAKE_CURRENT_SOURCE_DIR}/third/unicorn/qemu/accel/tcg/cputlb.c)
# icpp only supports x86_64/arm64 currently
set(UNICORN_ARCH "x86;aarch64" CACHE STRING "" FORCE)
# unicorn likes to check it from CFLAGS
set(CMAKE_MSVC_RUNTIME_LIBRARY_backup ${CMAKE_MSVC_RUNTIME_LIBRARY})
unset(CMAKE_MSVC_RUNTIME_LIBRARY)
add_subdirectory(third/unicorn)
set(CMAKE_MSVC_RUNTIME_LIBRARY ${CMAKE_MSVC_RUNTIME_LIBRARY_backup})

# icpp project
add_subdirectory(vmpstudio)
add_subdirectory(src)
