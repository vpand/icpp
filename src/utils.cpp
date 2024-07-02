/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "utils.h"
#include "platform.h"
#include <array>
#include <cstdlib>
#include <format>
#include <random>

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
                      path.c_str());
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

} // namespace icpp
