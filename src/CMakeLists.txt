message(STATUS "Configuring C++ interpreter icpp...")

# c++
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED)

if(MSVC)
  # enable exception for icpp relational projects
  set(LLVM_ENABLE_EH TRUE)
  set(LLVM_ENABLE_RTTI TRUE)
  # disable mscrt insecure warnings
  add_compile_definitions(-D_CRT_SECURE_NO_WARNINGS=1)
  # add boost config
  add_compile_definitions(-D_WIN32_WINNT=0x0601)
elseif(APPLE)
  add_link_options(-Wl,-rpath,@executable_path 
                   -Wl,-rpath,@executable_path/../lib
                   -Wl,-rpath,@executable_path/../lib/boost)
else()
  add_link_options(@${CMAKE_CURRENT_SOURCE_DIR}/ld.txt)
endif()

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

set(THIRD_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../third)
set(LLVM_OBJDUMP_ROOT ${THIRD_ROOT}/llvm-project/llvm/tools/llvm-objdump)
set(CLANG_DRIVER_ROOT ${THIRD_ROOT}/llvm-project/clang/tools/driver)

execute_process(COMMAND ${CMAKE_COMMAND} -E copy
  ${CMAKE_CURRENT_SOURCE_DIR}/icpp-driver.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/icpp-driver.cpp)

# generate the protocol sources with protoc
add_custom_command(
  OUTPUT 
    icppdbg.pb.cc icppiobj.pb.cc isymhash.pb.cc 
    icppmod.pb.cc
    icpppad.pb.cc
  COMMAND ${CMAKE_BINARY_DIR}/third/protobuf/protoc 
    -I=${CMAKE_SOURCE_DIR}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${CMAKE_SOURCE_DIR}/proto/icppdbg.proto
  COMMAND ${CMAKE_BINARY_DIR}/third/protobuf/protoc 
    -I=${CMAKE_SOURCE_DIR}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${CMAKE_SOURCE_DIR}/proto/icppiobj.proto
  COMMAND ${CMAKE_BINARY_DIR}/third/protobuf/protoc 
    -I=${CMAKE_SOURCE_DIR}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${CMAKE_SOURCE_DIR}/proto/isymhash.proto
  COMMAND ${CMAKE_BINARY_DIR}/third/protobuf/protoc 
    -I=${CMAKE_SOURCE_DIR}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${CMAKE_SOURCE_DIR}/proto/icppmod.proto
  COMMAND ${CMAKE_BINARY_DIR}/third/protobuf/protoc 
    -I=${CMAKE_SOURCE_DIR}/proto --cpp_out=${CMAKE_CURRENT_BINARY_DIR} 
       ${CMAKE_SOURCE_DIR}/proto/icpppad.proto
  DEPENDS ${CMAKE_SOURCE_DIR}/proto/icppdbg.proto
          ${CMAKE_SOURCE_DIR}/proto/icppiobj.proto
          ${CMAKE_SOURCE_DIR}/proto/isymhash.proto
          ${CMAKE_SOURCE_DIR}/proto/icppmod.proto
          ${CMAKE_SOURCE_DIR}/proto/icpppad.proto
  VERBATIM)

# llvm disabled rtti, so sources depend on them should also apply it
file(GLOB ICPP_LLVM_SOURCES
  compile.cpp
  object.cpp
  object-coff.cpp
  object-llvm.cpp
  ${LLVM_OBJDUMP_ROOT}/SourcePrinter.cpp
  ${CLANG_DRIVER_ROOT}/driver.cpp
  ${CLANG_DRIVER_ROOT}/cc1_main.cpp
  ${CLANG_DRIVER_ROOT}/cc1as_main.cpp
  ${CLANG_DRIVER_ROOT}/cc1gen_reproducer_main.cpp
)

file(GLOB ICPP_CORE_SOURCES
  arch.cpp
  debugger.cpp
  exec.cpp
  icpp.cpp
  loader.cpp
  log.cpp
  platform.cpp
  profile.cpp
  runcfg.cpp
  runtime.cpp
  trace.cpp
  utils.cpp
)

# we have patched this macro to build an icpp shared library, 
# because of this, you can deploy icpp to any kind of runtime environment.
add_clang_tool(icpp
  ${ICPP_CORE_SOURCES}
  icpp-driver.cpp
  icpp-main.cpp
  icpp-repl.cpp

  # auto generated by protoc
  icppdbg.pb.cc
  icppiobj.pb.cc
  isymhash.pb.cc

  # llvm relational files
  ${ICPP_LLVM_SOURCES}
  
  PARTIAL_SOURCES_INTENDED

  DEPENDS
  intrinsics_gen
  # These generated headers are included transitively.
  ARMTargetParserTableGen
  AArch64TargetParserTableGen
  ${support_plugins}
  GENERATE_DRIVER
)

if(MSVC)
  set(DISABLE_RTTI /GR-)
else()
  set(DISABLE_RTTI -fno-rtti)
  set_target_properties(icpp PROPERTIES VERSION ${CLANG_EXECUTABLE_VERSION})
endif()
set_source_files_properties(${ICPP_LLVM_SOURCES} PROPERTIES COMPILE_FLAGS ${DISABLE_RTTI})

clang_target_link_libraries(icpp
  PRIVATE
  clangBasic
  clangCodeGen
  clangDriver
  clangFrontend
  clangFrontendTool
  clangSerialization

  unicorn
  boost_algorithm
  boost_asio
  boost_beast
  boost_json
  libprotobuf
  brotlienc
  brotlidec
)
  
target_include_directories(icpp PRIVATE
  ${THIRD_ROOT}/llvm-project/llvm/include
  ${THIRD_ROOT}/llvm-project/clang/include
  ${LLVM_OBJDUMP_ROOT}
  ${THIRD_ROOT}/unicorn/include
  ${CMAKE_BINARY_DIR}
  ${CMAKE_BINARY_DIR}/third/llvm-project/llvm/include
  ${CMAKE_BINARY_DIR}/third/llvm-project/llvm/tools/clang/include
  ${CMAKE_CURRENT_BINARY_DIR}
  ${THIRD_ROOT}/brotli/c/include

  boost_algorithm
  boost_asio
  boost_beast
  boost_json
  libprotobuf
)

if(APPLE)
  target_link_options(icpp PRIVATE -Wl,-exported_symbol -Wl,_icpp_main)
elseif(LINUX)
  target_link_options(icpp PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/ld-icpp.version)
elseif(WIN32)
  target_link_directories(icpp PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
endif()

# remove lib prefix on macOS/Linux
set_target_properties(icpp PROPERTIES PREFIX "")

add_dependencies(icpp clang-resource-headers)

# icpp command line
add_executable(icppcli icpp-cli.cpp)
set_target_properties(icppcli PROPERTIES OUTPUT_NAME "icpp")
target_include_directories(icppcli PRIVATE 
  ${CMAKE_BINARY_DIR}/third/llvm-project/llvm/include
  boost_dll
)
if(MSVC)
  # on windows, use static link to load icpp.dll, the reason is as follows:
  # 1.the executable directory is the dll loading directory;
  # 2.only this way can have a better debugging experience in vscode;
  target_link_libraries(icppcli PRIVATE icpp)
else()
  # on macOS/Linux, use dlopen to load icpp.so/dylib, the reason is as follows:
  # we don't need to set any extra runtime path to make dyld/linker working correctly,
  # e.g.: .so rpath, .dylib install name, etc.
  target_link_libraries(icppcli PRIVATE boost_dll)
endif()

# icpp module manager command line
message(STATUS "Configuring icpp module manager imod...")

set(LLVM_LINK_COMPONENTS
  Object
  Option
  Support
)
file(GLOB IMOD_LLVM_SOURCES
  icpp-mod.cpp
  object.cpp
  object-coff.cpp
)
add_llvm_tool(imod 
  ${IMOD_LLVM_SOURCES}
  arch.cpp
  icpp.cpp
  loader.cpp
  platform.cpp
  runcfg.cpp
  runtime.cpp
  utils.cpp
  imod/createcfg.cpp
  isymhash.pb.cc
  icppmod.pb.cc
  icppiobj.pb.cc

  PARTIAL_SOURCES_INTENDED
)
set_source_files_properties(${IMOD_LLVM_SOURCES} PROPERTIES COMPILE_FLAGS ${DISABLE_RTTI})
target_include_directories(imod PRIVATE
  ${THIRD_ROOT}/llvm-project/llvm/include
  ${CMAKE_BINARY_DIR}/third/llvm-project/llvm/include
  ${THIRD_ROOT}/brotli/c/include
  ${CMAKE_CURRENT_BINARY_DIR}
  boost_asio
  boost_beast
  boost_json
  boost_process
  libprotobuf
)
target_link_libraries(imod PRIVATE
  boost_asio
  boost_beast
  boost_json
  boost_process
  brotlienc
  brotlidec
  libprotobuf
)

# iopad, sending the interpretable object to the remote 
# icpp gadget to execute it through nework
message(STATUS "Configuring interpretable object launch pad iopad...")

set(LLVM_LINK_COMPONENTS
  Option
  Support
)
file(GLOB IOPAD_LLVM_SOURCES
  icpp-pad.cpp
)
add_llvm_tool(iopad 
  ${IOPAD_LLVM_SOURCES}
  arch.cpp
  icpp.cpp
  platform.cpp
  runcfg.cpp
  utils.cpp
  icpppad.pb.cc

  PARTIAL_SOURCES_INTENDED
)
set_source_files_properties(${IOPAD_LLVM_SOURCES} PROPERTIES COMPILE_FLAGS ${DISABLE_RTTI})
target_include_directories(iopad PRIVATE 
  ${THIRD_ROOT}/llvm-project/llvm/include
  ${CMAKE_BINARY_DIR}/third/llvm-project/llvm/include
  ${CMAKE_CURRENT_BINARY_DIR}
  boost_asio
  boost_json
  boost_process
  libprotobuf
)
target_link_libraries(iopad PRIVATE 
  boost_asio
  boost_json
  boost_process
  libprotobuf
)

# icpp gadget, running as a daemon in somewhere to receive the
# interpretable object to execute
message(STATUS "Configuring memory resident interpreter icpp-gadget...")
set(LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
  Object
  Option
  Support
)
file(GLOB IGADGET_LLVM_SOURCES
  icpp-gadget.cpp
  object.cpp
  object-coff.cpp
  object-llvm.cpp
  ${LLVM_OBJDUMP_ROOT}/SourcePrinter.cpp
)
add_llvm_library(icpp-gadget SHARED 
  ${ICPP_CORE_SOURCES}

  # llvm relational files
  ${IGADGET_LLVM_SOURCES}

  # auto generated by protoc
  icppdbg.pb.cc
  icppiobj.pb.cc
  isymhash.pb.cc
  icpppad.pb.cc

  PARTIAL_SOURCES_INTENDED
)
set_target_properties(icpp-gadget PROPERTIES PREFIX "")
set_source_files_properties(${IGADGET_LLVM_SOURCES} PROPERTIES COMPILE_FLAGS ${DISABLE_RTTI})
target_include_directories(icpp-gadget PRIVATE 
  ${THIRD_ROOT}/llvm-project/llvm/include
  ${CMAKE_BINARY_DIR}/third/llvm-project/llvm/include
  ${THIRD_ROOT}/unicorn/include
  ${CMAKE_CURRENT_BINARY_DIR}
  ${LLVM_OBJDUMP_ROOT}
  boost_asio
  boost_beast
  boost_json
  libprotobuf
)
target_link_libraries(icpp-gadget PRIVATE 
  boost_asio
  boost_beast
  boost_json
  libprotobuf
  unicorn
)
if(APPLE)
  target_link_options(icpp-gadget PRIVATE -Wl,-exported_symbol -Wl,_icpp_gadget)
elseif(LINUX)
  target_link_options(icpp-gadget PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/ld-gadget.version)
elseif(WIN32)
  target_link_directories(icpp-gadget PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
endif()

# icpp-server command line
message(STATUS "Configuring icpp-server remote daemon...")
add_executable(icpp-server icpp-server.cpp)
target_include_directories(icpp-server PRIVATE 
  ${CMAKE_BINARY_DIR}/third/llvm-project/llvm/include
  boost_dll
)
if(MSVC)
  # on windows, use static link to load icpp-gadget.dll, the reason is as follows:
  # 1.the executable directory is the dll loading directory;
  # 2.only this way can have a better debugging experience in vscode;
  target_link_libraries(icpp-server PRIVATE icpp-gadget)
else()
  # on macOS/Linux, use dlopen to load icpp-gadget.so/dylib, the reason is as follows:
  # we don't need to set any extra runtime path to make dyld/linker working correctly,
  # e.g.: .so rpath, .dylib install name, etc.
  target_link_libraries(icpp-server PRIVATE boost_dll)
endif()

message(STATUS "Configuring icpp done")
