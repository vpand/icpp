/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <chrono>
#include <ctime>
#include <format>
#include <iomanip>
#include <iostream>
#include <string_view>

namespace icpp {

enum LogType {
  Develop,
  Runtime,
  Raw,
};

template <typename... Args>
inline void log_print(LogType type, std::format_string<Args...> format,
                      Args &&...args) {
  bool commit = false;
  char tchar = ' ';
  switch (type) {
  case Develop:
#if DEBUG || _DEBUG || !NDEBUG
    commit = true;
    tchar = 'D';
#endif
    break;
  case Runtime:
    commit = true;
    tchar = 'R';
    break;
  case Raw:
    commit = true;
    break;
  default:
    return;
  }
  if (!commit)
    return;
  if (type != Raw) {
    auto now = std::time(nullptr);
    std::cout << std::put_time(std::localtime(&now), "%T") << " " << tchar
              << " - ";
  }
  std::cout << std::vformat(format.get(), std::make_format_args(args...))
            << std::endl;
}

template <typename... Args>
inline void log_print(std::string_view prefix,
                      std::format_string<Args...> format, Args &&...args) {
  std::cout << prefix
            << std::vformat(format.get(), std::make_format_args(args...))
            << std::endl;
}

} // namespace icpp
