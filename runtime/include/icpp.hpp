/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

// ICPP Standard C/C++ Utilities' Implementation

#pragma once

// architecture type
#if __arm64__ || __aarch64__
#define __ARM64__ 1
#elif __x86_64__ || __x64__ || _M_AMD64 || _M_X64
#define __X64__ 1
#endif

// os type
#if defined(_WIN32) || defined(_WIN64)
#define __WIN__ 1
#else
#define __UNIX__ 1
#if __linux__
#define __LINUX__ 1
#endif
#if ANDROID
#define __ANDROID__ 1
#endif
// __APPLE__ on macOS/iOS
#endif

#ifdef __WIN__
#ifdef ICPP_DLLIMPL
#define ICPP_API __declspec(dllexport)
#else
#define ICPP_API __declspec(dllimport)
#endif // end of ICPP_DLLIMPL
#else
#define ICPP_API __attribute__((visibility("default")))
#endif // end of __WIN__

// for standard c++ definitions
#if __ICPP_CROSS__ || ICPP_DLLIMPL
// c style
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <regex>
#include <string>
#include <string_view>
#else
// c++ module style
import std;
#endif

namespace fs = std::filesystem;

// make it easy to use string literals
using namespace std::literals::string_literals;
using namespace std::literals::string_view_literals;

namespace icpp {

/*
Common Utilities
*/

// string list type
using strings = std::vector<std::string>;
using string_views = std::vector<std::string_view>;

// for desktop platform
#if __APPLE__
#define LIB_EXT ".dylib"
#define EXE_EXT ""
constexpr std::string_view platform = "apple";
constexpr std::string_view os_name = "macos";
#elif __linux__
#define LIB_EXT ".so"
#define EXE_EXT ""
constexpr std::string_view platform = "linux";
constexpr std::string_view os_name = "linux";
#else
#define LIB_EXT ".dll"
#define EXE_EXT ".exe"
constexpr std::string_view platform = "win";
constexpr std::string_view os_name = "windows";
#endif
constexpr std::string_view lib_ext = LIB_EXT;
constexpr std::string_view exe_ext = EXE_EXT;

#if __aarch64__ || __arm64__
#if __linux__
constexpr std::string_view arch = "aarch64";
#else
constexpr std::string_view arch = "arm64";
#endif
#else
constexpr std::string_view arch = "x86_64";
#endif

/*
ICPP Specification
*/

// the icpp interpreter version
ICPP_API std::string_view version();

// the icpp main program argv[0] path
ICPP_API std::string_view program();

// the current user home directory, e.g.: ~, C:/Users/icpp
ICPP_API std::string_view home();

// execute a c++ expression
ICPP_API int exec_expression(std::string_view expr);

// execute a c++ source from string
ICPP_API int exec_string(std::string_view code, int argc = 0,
                         const char **argv = nullptr);

// execute a c++ source file
ICPP_API int exec_source(std::string_view path, int argc = 0,
                         const char **argv = nullptr);

// execute an icpp module installed by imod
ICPP_API int exec_module(std::string_view module, int argc = 0,
                         const char **argv = nullptr);

// result setter/getter for main script and its sub script
// which is executed by exec_* api
/*
e.g.:
  icpp::exec_expression("result_set(520)");
  icpp::prints("Result: {}", result_get());
*/
ICPP_API void result_set(std::uint64_t result);
ICPP_API void result_set(const std::string_view &result);
ICPP_API std::uint64_t result_get();
ICPP_API std::string_view result_gets();

// load a native library
ICPP_API void *load_library(std::string_view path);
// unload a native library
ICPP_API void *unload_library(void *handle);
// lookup a native symbol
// default search in the whole program
ICPP_API void *resolve_symbol(std::string_view name, void *handle = nullptr);
// iterate all the native library modules in this running process,
// return true to break iterating
ICPP_API void iterate_library(
    const std::function<bool(std::uint64_t base, std::string_view path)>
        &callback);

// random value or string generator
ICPP_API int rand_int();
ICPP_API std::string rand_str(int length);

struct ICPP_API regex {
  regex(std::string_view pattern, int flags = std::regex_constants::ECMAScript |
                                              std::regex_constants::icase) {
    init(pattern, flags);
  }
  ~regex() { deinit(); }
  regex() = delete;

  // return true if str matches the initial pattern
  bool search(std::string_view str) const;

private:
  void init(std::string_view pattern, int flags);
  void deinit();
  void *context_;
};

ICPP_API void print(std::uint64_t val);
ICPP_API void print_hex(std::uint64_t val);

} // namespace icpp
