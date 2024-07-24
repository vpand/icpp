/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
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

// for boost definitions
#include <boost/algorithm/string.hpp>

// for standard c++ definitions
#if 0
// c style
#include <filesystem>
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

// c++ std::format like print implementation
template <typename... Args>
static inline int prints(std::format_string<Args...> format, Args &&...args) {
  auto str = std::vformat(format.get(), std::make_format_args(args...));
  return std::printf("%s", str.data());
}

// split a string with a string delimiter
static inline strings split(const std::string &str,
                            const std::string &delimiter) {
  strings parts;
  boost::iter_split(parts, str, boost::first_finder(delimiter));
  return parts;
}

/*
ICPP Specification
*/

// the icpp interpreter version
std::string_view version();

// the icpp main program argv[0] path
std::string_view program();

// the current user home directory, e.g.: ~, C:/Users/icpp
std::string_view home_directory();

// execute a c++ expression
int exec_expression(std::string_view expr);

// execute a c++ source from string
int exec_string(std::string_view code, int argc = 0,
                const char **argv = nullptr);

// execute a c++ source file
int exec_source(std::string_view path, int argc = 0,
                const char **argv = nullptr);

// execute an icpp module installed by imod
int exec_module(std::string_view module, int argc = 0,
                const char **argv = nullptr);

// result setter/getter for main script and its sub script
// which is executed by exec_* api
/*
e.g.:
  icpp::exec_expression("result_set(520)");
  icpp::prints("Result: {}", result_get());
*/
void result_set(long result);
void result_set(const std::string_view &result);
long result_get();
std::string_view result_gets();

// load a native library
void *load_library(std::string_view path);
// unload a native library
void *unload_library(void *handle);
// lookup a native symbol
// default search in the whole program
void *resolve_symbol(std::string_view name, void *handle = nullptr);
// iterate all the native modules in this running process,
// return true to break iterating
void iterate_modules(
    const std::function<bool(uint64_t base, std::string_view path)> &callback);

// check whether the given path ends with a c++ source file extension or not
bool is_cpp_source(std::string_view path);

// random value or string generator
int rand_value();
/*
The better prototype should be: std::string rand_string(int length = 8);
But on Windows, icpp itself is built by clang-cl in Visual Studio, icpp.hpp
will be built by clang-icpp, so the std::string may be defined in a different
way, to avoid the type mismatch, herein gives it an old C style one.

As of this, if you want to extend icpp runtime with native modules, the type
mismatch situation must be considered on Windows.
*/
std::string_view rand_string(char *buff, int length);

/*
Wrapper Utilities
*/

template <size_t N> std::string rand_string() {
  char buff[N];
  auto tstr = rand_string(buff, N);
  return {tstr.data(), N};
}

} // namespace icpp
