/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

// for boost definitions
#include <boost/algorithm/string.hpp>
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
namespace bp = boost::process;

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

// execute program with args and process the output lines with procline callback
static inline void
execute(const std::string &program, const strings &args,
        const std::function<void(std::string_view)> &procline) {
  bp::ipstream is; // reading pipe-stream
  // cmd args > is
  bp::child(program, args, bp::std_out > is).wait();

  std::string line;
  // read the output lines
  while (std::getline(is, line))
    procline(line);
}

// execute program with args, return the output string
static inline std::string execute(const std::string &program,
                                  const strings &args) {
  std::string output;
  execute(program, args, [&output](std::string_view line) { output += line; });
  return output;
}

// execute program with args, return the output lines
static inline strings execute2(const std::string &program,
                               const strings &args) {
  strings output;
  execute(program, args,
          [&output](std::string_view line) { output.push_back(line.data()); });
  return output;
}

// execute cmd with args, return the output string
static inline std::string command(const std::string &cmd, const strings &args) {
  return execute(bp::search_path(cmd).string(), args);
}

// execute cmd with args, return the output lines
static inline strings command2(const std::string &cmd, const strings &args) {
  return execute2(bp::search_path(cmd).string(), args);
}

} // namespace icpp
