/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "utils.h"
#include "platform.h"
#include <array>
#include <boost/algorithm/string.hpp>
#include <cstdlib>
#include <format>
#include <random>
#include <set>

namespace icpp {

void CondMutex::wait() {
  std::unique_lock lock(mutex);
  cond.wait(lock);
}

void CondMutex::signal() { cond.notify_all(); }

bool is_cpp_source(std::string_view path) {
  for (auto ext :
       std::array{".c", ".cc", ".cpp", ".cxx", ".C", ".CC", ".CPP", ".CXX"}) {
    if (path.ends_with(ext)) {
      return true;
    }
  }
  return false;
}

int rand_value() {
  std::mt19937 mt(time(nullptr));
  return mt();
}

std::string rand_string(int length) {
  std::mt19937 mt(time(nullptr));
  std::string result;
  for (int i = 0; i < length; i++) {
    unsigned rv = mt();
    // generate a 0-f character at a time
    result.append(std::format("{:x}", rv % 16));
  }
  return result;
}

std::string rand_filename(int length, std::string_view ext) {
  return rand_string(length) + std::string(ext);
}

std::string home_directory() { return std::getenv(env_home.data()); }

fs::path must_exist(const fs::path &path) {
  if (!fs::exists(path)) {
    if (!fs::create_directories(path)) {
      icpp::log_print(Runtime, "Fatal error, failed to create directory {}.",
                      path.string());
      std::exit(-1);
    }
  }
  return path;
}

fs::path convert_file(std::string_view path, std::string_view newext) {
  auto srcpath = fs::path(path);
  auto cachepath = fs::absolute(srcpath.parent_path()) /
                   (srcpath.stem().string() + newext.data());
  if (!fs::exists(cachepath)) {
    // there's no cache file
    return "";
  }
  auto srctm = fs::last_write_time(srcpath);
  auto objtm = fs::last_write_time(cachepath);
  if (srctm > objtm) {
    // source has been updated, so the cache file becomes invalid
    return "";
  }
  return cachepath;
}

int repl_entry(const std::function<void(std::string_view)> &exec) {
  std::set<std::string> directives;
  std::string lastsnippet;
  while (!std::cin.eof()) {
    std::string snippet;
    std::cout << ">>> ";
    std::getline(std::cin, snippet);
    boost::trim<std::string>(snippet);
    if (!snippet.length()) {
      if (!lastsnippet.length())
        continue;
      // repeat the last snippet if nothing input
      snippet = lastsnippet;
    }

    // only support ascii snippet input
    bool valid = true;
    for (auto c : snippet) {
      if (!std::isprint(c)) {
        valid = false;
        break;
      }
    }
    if (!valid) {
      std::cout << "Ignored this non ascii snippet code: " << snippet
                << std::endl;
      continue;
    }

    if (snippet.starts_with("#") || snippet.starts_with("typedef ") ||
        snippet.starts_with("using ") || snippet.starts_with("namespace ") ||
        snippet.starts_with(R"(extern "C")")) {
      // accumulated compiler directives, like #include, #define, etc.
      directives.insert(snippet);
      continue;
    }

    std::string dyncodes;
    // the # prefixed compiler directives
    for (auto &d : directives)
      dyncodes += d + "\n";
    // the main entry
    dyncodes += "int main(void) {" + snippet + ";return 0;}";
    exec(dyncodes);
    lastsnippet = snippet;
  }
  return 0;
}

void iterate_pathenv(
    const std::function<IterateState(std::string_view path)> &callback) {
  std::vector<std::string> paths;
  for (auto &p :
       boost::split(paths, std::getenv("PATH"), boost::is_any_of(path_split))) {
    if (callback(p) == IterBreak)
      break;
  }
}

} // namespace icpp
