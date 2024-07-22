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
#include <boost/process.hpp>

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

} // namespace icpp
