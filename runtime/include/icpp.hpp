/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

// ICPP Standard C/C++ Utilities' Implementation

#pragma once

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
