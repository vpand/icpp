# modified from https://github.com/mickem/google-breakpad/blob/master/CMakeLists.txt

project(breakpad)
cmake_minimum_required(VERSION 3.20)

# c++
SET(CMAKE_CXX_STANDARD 20)
SET(CMAKE_CXX_STANDARD_REQUIRED)

IF(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
SET(BREAKPAD_SRC_DIR ${CMAKE_SOURCE_DIR}/../../third/breakpad/src)
ELSE()
SET(BREAKPAD_SRC_DIR ${CMAKE_SOURCE_DIR}/third/breakpad/src)
ENDIF()

IF(NOT DEFINED BREAKPAD_LIBRARY_TYPE)
  SET(BREAKPAD_LIBRARY_TYPE "STATIC" CACHE STRING "Type of library to build, STATIC, SHARED or BOTH.")
ELSE()
  SET(BREAKPAD_LIBRARY_TYPE ${BREAKPAD_LIBRARY_TYPE} CACHE STRING "Type of library to build, STATIC or SHARED.")
ENDIF()


STRING(TOUPPER ${BREAKPAD_LIBRARY_TYPE} BREAKPAD_LIBRARY_TYPE_UPPER)
STRING(COMPARE EQUAL "${BREAKPAD_LIBRARY_TYPE_UPPER}" "STATIC" BREAKPAD_STATIC)
IF(NOT BREAKPAD_STATIC)
	STRING(COMPARE EQUAL "${BREAKPAD_LIBRARY_TYPE_UPPER}" "BOTH" BREAKPAD_STATIC)
ENDIF()
STRING(COMPARE EQUAL "${BREAKPAD_LIBRARY_TYPE_UPPER}" "SHARED" BREAKPAD_SHARED)
IF(NOT BREAKPAD_SHARED)
	STRING(COMPARE EQUAL "${BREAKPAD_LIBRARY_TYPE_UPPER}" "BOTH" BREAKPAD_SHARED)
ENDIF()


if(WIN32)
	set(DEBUG_ACCESS_SDK_DIR "$ENV{VSINSTALLDIR}/DIA SDK")
	
	add_definitions(-DUNICODE -D_UNICODE)

	
	SET(CompilerFlags
		CMAKE_CXX_FLAGS
		CMAKE_CXX_FLAGS_DEBUG
		CMAKE_CXX_FLAGS_RELEASE
		CMAKE_C_FLAGS
		CMAKE_C_FLAGS_DEBUG
		CMAKE_C_FLAGS_RELEASE
		)
	IF(BREAKPAD_STATIC_RUNTIME)
		IF(WIN32)
			FOREACH(CompilerFlag ${CompilerFlags})
				STRING(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
				STRING(REPLACE "/MDd" "/MTd" ${CompilerFlag} "${${CompilerFlag}}")
			ENDFOREACH()
		ENDIF()
	ELSE()
		IF(WIN32)
			FOREACH(CompilerFlag ${CompilerFlags})
				STRING(REPLACE "/MT" "/MD" ${CompilerFlag} "${${CompilerFlag}}")
				STRING(REPLACE "/MTd" "/MDd" ${CompilerFlag} "${${CompilerFlag}}")
			ENDFOREACH()
		ENDIF()
	ENDIF()

	
	include_directories(${BREAKPAD_SRC_DIR} ${BREAKPAD_SRC_DIR}/third_party/windows/include ${DEBUG_ACCESS_SDK_DIR}/include)
	set(BREAKPADCOMMON_LIB_SRCS
		${BREAKPAD_SRC_DIR}/common/windows/guid_string.cc
		${BREAKPAD_SRC_DIR}/common/windows/string_utils.cc
		${BREAKPAD_SRC_DIR}/common/windows/http_upload.cc
	)
	set(BREAKPADCOMMON_LIBS Imagehlp)

	set(CLIENT_SRC_DIR ${BREAKPAD_SRC_DIR}/client/windows)
	set(BREAKPAD_LIB_SRCS
		${CLIENT_SRC_DIR}/handler/exception_handler.cc
		${CLIENT_SRC_DIR}/crash_generation/client_info.cc
		${CLIENT_SRC_DIR}/crash_generation/crash_generation_client.cc
		${CLIENT_SRC_DIR}/crash_generation/crash_generation_server.cc
		${CLIENT_SRC_DIR}/crash_generation/minidump_generator.cc
	)
	#ide_group_sources("${BREAKPAD_LIB_SRCS}")
	
	if (EXISTS "${DEBUG_ACCESS_SDK_DIR}")

		set(DUMPSYMS_SRCS
				# pdb_source_line_writer.cc is linked into the `dump_syms` target rather than
				# `breakpad_common` to avoid a runtime dependency on the DIA SDK libs
				# in the breakpad client library
				${BREAKPAD_SRC_DIR}/common/windows/pdb_source_line_writer.cc
				${BREAKPAD_SRC_DIR}/common/windows/omap.cc
				${BREAKPAD_SRC_DIR}/common/windows/dia_util.cc
				${BREAKPAD_SRC_DIR}/tools/windows/dump_syms/dump_syms.cc
		)
		if(CMAKE_CL_64)
			find_library(DIA_SDK_GUID_LIB diaguids PATHS ${DEBUG_ACCESS_SDK_DIR}/lib/amd64)
		else()
			find_library(DIA_SDK_GUID_LIB diaguids PATHS ${DEBUG_ACCESS_SDK_DIR}/lib)
		endif()
		set(DUMPSYMS_LIBS ${DIA_SDK_GUID_LIB})
		set(BUILD_DUMPSYMS TRUE)
	else()
		# The Debug Access SDK is required to build the dump_syms tool.
		# It ships with the pro versions of Visual Studio 2008 and 2010 but not
		# the express versions. It is available separately as part of the Windows SDK
		# however.
		message(STATUS "Debug Access SDK not found in ${DEBUG_ACCESS_SDK_DIR}")
		set(BUILD_DUMPSYMS FALSE)
	endif()
elseif(APPLE)
	set(CLIENT_SRC_DIR ${BREAKPAD_SRC_DIR}/client/mac)
	include_directories(${BREAKPAD_SRC_DIR} ${BREAKPAD_SRC_DIR}/third_party/mac/include)
	add_definitions(-DHAVE_MACH_O_NLIST_H)
	file(GLOB BREAKPADCOMMON_LIB_SRCS
		${BREAKPAD_SRC_DIR}/common/convert_UTF.cc
		${BREAKPAD_SRC_DIR}/common/mac/MachIPC.mm
		${BREAKPAD_SRC_DIR}/common/mac/bootstrap_compat.cc
		${BREAKPAD_SRC_DIR}/common/mac/file_id.cc
		${BREAKPAD_SRC_DIR}/common/mac/macho_id.cc
		${BREAKPAD_SRC_DIR}/common/mac/macho_utilities.cc
		${BREAKPAD_SRC_DIR}/common/mac/macho_walker.cc
		${BREAKPAD_SRC_DIR}/common/mac/string_utilities.cc
		${BREAKPAD_SRC_DIR}/common/md5.cc
		${BREAKPAD_SRC_DIR}/common/string_conversion.cc
    ${BREAKPAD_SRC_DIR}/common/mac/arch_utilities.cc
	)

	set(BREAKPAD_LIB_SRCS
		${BREAKPAD_SRC_DIR}/client/minidump_file_writer.cc
		${CLIENT_SRC_DIR}/crash_generation/crash_generation_client.cc
		${CLIENT_SRC_DIR}/crash_generation/crash_generation_server.cc
		${CLIENT_SRC_DIR}/handler/breakpad_nlist_64.cc
		${CLIENT_SRC_DIR}/handler/dynamic_images.cc
		${CLIENT_SRC_DIR}/handler/exception_handler.cc
		${CLIENT_SRC_DIR}/handler/minidump_generator.cc
	)

	set(DUMPSYMS_SRCS
		${BREAKPAD_SRC_DIR}/common/dwarf/bytereader.cc
		${BREAKPAD_SRC_DIR}/common/dwarf/dwarf2diehandler.cc
		${BREAKPAD_SRC_DIR}/common/dwarf/dwarf2reader.cc
		${BREAKPAD_SRC_DIR}/common/dwarf_cfi_to_module.cc
		${BREAKPAD_SRC_DIR}/common/dwarf_cu_to_module.cc
		${BREAKPAD_SRC_DIR}/common/dwarf_line_to_module.cc
		${BREAKPAD_SRC_DIR}/common/language.cc
		${BREAKPAD_SRC_DIR}/common/mac/dump_syms.mm
		${BREAKPAD_SRC_DIR}/common/mac/macho_reader.cc
		${BREAKPAD_SRC_DIR}/common/module.cc
		${BREAKPAD_SRC_DIR}/common/stabs_reader.cc
		${BREAKPAD_SRC_DIR}/common/stabs_to_module.cc
		${BREAKPAD_SRC_DIR}/tools/mac/dump_syms/dump_syms_tool.mm
	)
	find_library(FOUNDATION_LIB Foundation REQUIRED)
	set(DUMPSYMS_LIBS ${FOUNDATION_LIB})

elseif(UNIX)
	add_definitions(-DHAVE_A_OUT_H)
	set(CLIENT_SRC_DIR ${BREAKPAD_SRC_DIR}/client/linux)
	include_directories(${BREAKPAD_SRC_DIR} ${BREAKPAD_SRC_DIR}/third_party/linux/include)
	set(BREAKPADCOMMON_LIB_SRCS
		${BREAKPAD_SRC_DIR}/common/convert_UTF.c
		${BREAKPAD_SRC_DIR}/common/linux/file_id.cc
		${BREAKPAD_SRC_DIR}/common/linux/guid_creator.cc
		${BREAKPAD_SRC_DIR}/common/linux/memory_mapped_file.cc
		${BREAKPAD_SRC_DIR}/common/linux/safe_readlink.cc
		${BREAKPAD_SRC_DIR}/common/string_conversion.cc
	)
	find_package(Threads)
	set(BREAKPADCOMMON_LIBS ${CMAKE_THREAD_LIBS_INIT})

	set(BREAKPAD_LIB_SRCS
		${CLIENT_SRC_DIR}/../minidump_file_writer.cc
		${CLIENT_SRC_DIR}/crash_generation/crash_generation_client.cc
		${CLIENT_SRC_DIR}/handler/exception_handler.cc
		${CLIENT_SRC_DIR}/log/log.cc
		${CLIENT_SRC_DIR}/minidump_writer/linux_dumper.cc
		${CLIENT_SRC_DIR}/minidump_writer/linux_ptrace_dumper.cc
		${CLIENT_SRC_DIR}/minidump_writer/minidump_writer.cc
	)
	
	set(DUMPSYMS_SRCS
		${BREAKPAD_SRC_DIR}/common/dwarf/bytereader.cc
		${BREAKPAD_SRC_DIR}/common/dwarf/dwarf2diehandler.cc
		${BREAKPAD_SRC_DIR}/common/dwarf/dwarf2reader.cc
		${BREAKPAD_SRC_DIR}/common/dwarf_cfi_to_module.cc
		${BREAKPAD_SRC_DIR}/common/dwarf_cu_to_module.cc
		${BREAKPAD_SRC_DIR}/common/dwarf_line_to_module.cc
		${BREAKPAD_SRC_DIR}/common/language.cc
		${BREAKPAD_SRC_DIR}/common/linux/dump_symbols.cc
		${BREAKPAD_SRC_DIR}/common/linux/elf_symbols_to_module.cc
		${BREAKPAD_SRC_DIR}/common/module.cc
		${BREAKPAD_SRC_DIR}/common/stabs_reader.cc
		${BREAKPAD_SRC_DIR}/common/stabs_to_module.cc
		${BREAKPAD_SRC_DIR}/tools/linux/dump_syms/dump_syms.cc
	)
endif()


# breakpad - client library for capturing minidumps when a crash occurs
IF(BREAKPAD_STATIC)
	message(STATUS "Adding static breakpad_lib")
	add_library(breakpad-static STATIC ${BREAKPAD_LIB_SRCS} ${BREAKPADCOMMON_LIB_SRCS})
ENDIF()
IF(BREAKPAD_SHARED)
	message(STATUS "Adding shared breakpad")
	add_library(breakpad SHARED ${BREAKPAD_LIB_SRCS} ${BREAKPADCOMMON_LIB_SRCS})
IF(APPLE)
  target_link_options(breakpad PRIVATE -framework Foundation)
ENDIF()
ENDIF()
