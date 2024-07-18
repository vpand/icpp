/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

// for boost definitions
#include <boost/algorithm/string.hpp>

// for standard c++ definitions
import std;

namespace icpp {

// c++ std::format like print implementation
template <typename... Args>
static inline int prints(LogType type, std::format_string<Args...> format,
                         Args &&...args) {
  auto str = std::vformat(format.get(), std::make_format_args(args...));
  return std::printf("%s", str);
}

// split a string with a string delimiter
static inline std::vector<std::string> split(const std::string &str,
                                             const std::string &delimiter) {
  std::vector<std::string> result;
  for (auto left = str; left.size();) {
    std::vector<std::string> parts;
    boost::iter_split(parts, str, boost::first_finder(delimiter));
    result.push_back(parts[0]);
    if (parts.size() == 1)
      break;
    left = parts[1];
  }
  return result;
}

} // namespace icpp
