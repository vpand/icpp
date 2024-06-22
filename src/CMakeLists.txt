message(STATUS "Configuring icpp...")

# c++
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED)

set(LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
  Analysis
  CodeGen
  Core
  IPO
  AggressiveInstCombine
  InstCombine
  Instrumentation
  MC
  MCParser
  ObjCARCOpts
  Option
  ScalarOpts
  Support
  TargetParser
  TransformUtils
  Vectorize
)

# Support plugins.
if(CLANG_PLUGIN_SUPPORT)
  set(support_plugins SUPPORT_PLUGINS)
endif()

set(THIRD_ROOT ../third)
set(CLANG_DRIVER_ROOT ${THIRD_ROOT}/llvm-project/clang/tools/driver)
execute_process(COMMAND ${CMAKE_COMMAND} -E copy
  ${CMAKE_CURRENT_SOURCE_DIR}/icpp-driver.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/icpp-driver.cpp)
add_clang_tool(icpp
  arch.cpp
  compile.cpp
  debugger.cpp
  exec.cpp
  icpp-driver.cpp
  icpp-main.cpp
  icpp.cpp
  loader.cpp
  log.cpp
  object.cpp
  platform.cpp
  profile.cpp
  runcfg.cpp
  runtime.cpp
  trace.cpp
  utils.cpp
  ${CLANG_DRIVER_ROOT}/driver.cpp
  ${CLANG_DRIVER_ROOT}/cc1_main.cpp
  ${CLANG_DRIVER_ROOT}/cc1as_main.cpp
  ${CLANG_DRIVER_ROOT}/cc1gen_reproducer_main.cpp
  ${CMAKE_BINARY_DIR}/vmpstudio/icppdbg.pb.cc
  
  PARTIAL_SOURCES_INTENDED

  DEPENDS
  intrinsics_gen
  # These generated headers are included transitively.
  ARMTargetParserTableGen
  AArch64TargetParserTableGen
  ${support_plugins}
  GENERATE_DRIVER
)

clang_target_link_libraries(icpp
  PRIVATE
  clangBasic
  clangCodeGen
  clangDriver
  clangFrontend
  clangFrontendTool
  clangSerialization

  unicorn
  boost_asio
  libprotobuf
)
  
target_include_directories(icpp PRIVATE
  ${THIRD_ROOT}/llvm-project/llvm/include
  ${THIRD_ROOT}/llvm-project/clang/include
  ${THIRD_ROOT}/unicorn/include
  ${CMAKE_BINARY_DIR}
  ${CMAKE_BINARY_DIR}/third/llvm-project/llvm/include
  ${CMAKE_BINARY_DIR}/third/llvm-project/llvm/tools/clang/include
  ${CMAKE_BINARY_DIR}/vmpstudio

  boost_asio
  libprotobuf
)

if(WIN32 AND NOT CYGWIN)
  # Prevent versioning if the buildhost is targeting for Win32.
else()
  set_target_properties(icpp PROPERTIES VERSION ${CLANG_EXECUTABLE_VERSION})
endif()

# Support plugins.
if(CLANG_PLUGIN_SUPPORT)
  export_executable_symbols_for_plugins(icpp)
endif()

add_dependencies(icpp clang-resource-headers)

message(STATUS "Configuring icpp done")
