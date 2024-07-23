# cmake
cmake_minimum_required(VERSION 3.20)
project(icpp CXX C ASM)

# is there any kind of defined variable like APPLE/MSVC for Linux ?
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(LINUX TRUE)
endif()

# workaround to fix wrong compiler on macOS
if(APPLE)
  set(CMAKE_C_COMPILER "/usr/bin/clang" CACHE FILEPATH "" FORCE)
endif()

# workaround to process the different python/build command line name
if(WIN32)
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
  set(protobuf_MSVC_STATIC_RUNTIME OFF)
else()
  set(PYTHON python3)
  set(BUILDCMD make)
  # make all the symbols hidden by default
  add_compile_options(-fvisibility=hidden -fvisibility-inlines-hidden)
endif()
if(LINUX)
  set(ICPPCLANG ${CMAKE_BINARY_DIR}/llvm)
  set(ICXXINCLUDE ${ICPPCLANG}/include)
  set(ICXXLIB ${ICPPCLANG}/lib/${CMAKE_HOST_SYSTEM_PROCESSOR}-unknown-linux-gnu)
  # apply our custom built libc++ compile/link flags
  add_compile_options(-nostdinc++ -nostdlib++ -fPIC -I${ICXXINCLUDE}/c++/v1 
    -I${ICXXINCLUDE}/${CMAKE_HOST_SYSTEM_PROCESSOR}-unknown-linux-gnu/c++/v1)
  add_link_options(-L${ICXXLIB} -lc -lm -lc++ @${CMAKE_SOURCE_DIR}/config/ld-${CMAKE_HOST_SYSTEM_PROCESSOR}.txt)
  # as we're already using the latest clang, any further checks are redundant
  set(LLVM_COMPILER_CHECKED TRUE)
  # set this variable to disable llvm's cmake to do any more checks, it's really annoying...
  set(LLVM_COMPILER_IS_GCC_COMPATIBLE FALSE)
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

# boost
message(STATUS "Configuring boost...")
if (WIN32)
  set(BOOST_CONTEXT_IMPLEMENTATION winfib)
endif()
add_subdirectory(third/boost)

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

# unicorn
message(STATUS "Configuring unicorn...")
# patch qemu mmu to enable the emulated code to access memory directly
execute_process(COMMAND ${PYTHON}
  ${CMAKE_CURRENT_SOURCE_DIR}/tool/qemu_mmu_patcher.py
  ${CMAKE_CURRENT_SOURCE_DIR}/third/unicorn/qemu/accel/tcg/cputlb.c)
# patch qemu tbgen buffer size to 64MB
execute_process(COMMAND ${PYTHON}
  ${CMAKE_CURRENT_SOURCE_DIR}/tool/qemu_tbgen_patcher.py
  ${CMAKE_CURRENT_SOURCE_DIR}/third/unicorn/qemu/softmmu/vl.c)
if(MSVC)
  # patch unicorn cmake to cmake correctly on Windows, otherwise it fails to cmake or run
  if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "ARM64")
    execute_process(COMMAND ${PYTHON}
      ${CMAKE_CURRENT_SOURCE_DIR}/tool/qemu_tcgop_patcher_arm64.py
      ${CMAKE_CURRENT_SOURCE_DIR}/third/unicorn/qemu/include/tcg/tcg-opc.h)
    execute_process(COMMAND ${PYTHON}
      ${CMAKE_CURRENT_SOURCE_DIR}/tool/qemu_tcgul_patcher_arm64.py
      ${CMAKE_CURRENT_SOURCE_DIR}/third/unicorn/qemu/tcg/aarch64/tcg-target.inc.c)
    execute_process(COMMAND ${PYTHON}
      ${CMAKE_CURRENT_SOURCE_DIR}/tool/unicorn_cmake_patcher_arm64.py
      ${CMAKE_CURRENT_SOURCE_DIR}/third/unicorn/CMakeLists.txt)
  else()
    execute_process(COMMAND ${PYTHON}
      ${CMAKE_CURRENT_SOURCE_DIR}/tool/unicorn_cmake_patcher.py
      ${CMAKE_CURRENT_SOURCE_DIR}/third/unicorn/CMakeLists.txt)
  endif()
endif()
# icpp only supports x86_64/arm64 currently
set(UNICORN_ARCH "x86;aarch64" CACHE STRING "" FORCE)
# unicorn likes to check it from CFLAGS
set(CMAKE_MSVC_RUNTIME_LIBRARY_backup ${CMAKE_MSVC_RUNTIME_LIBRARY})
unset(CMAKE_MSVC_RUNTIME_LIBRARY)
add_subdirectory(third/unicorn)
set(CMAKE_MSVC_RUNTIME_LIBRARY ${CMAKE_MSVC_RUNTIME_LIBRARY_backup})

#
# icpp projects
#

add_subdirectory(vmpstudio)
add_subdirectory(src)
