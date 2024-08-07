/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include "log.h"
#include <filesystem>
#include <functional>
#include <mutex>
#include <string_view>

namespace fs = std::filesystem;

#define UNIMPL_ABORT()                                                         \
  {                                                                            \
    icpp::log_print(icpp::Runtime, "Un-implement {},{},{} currently yet.",     \
                    __FILE__, __FUNCTION__, __LINE__);                         \
    abort();                                                                   \
  }

namespace icpp {

struct CondMutex {
  std::mutex mutex;
  std::condition_variable cond;

  void wait();
  void signal();
};

struct ProtocolHdr {
  std::uint32_t cmd : 8, // command id
      len : 24;          // protobuf length
};

enum IterateState {
  IterContinue,
  IterBreak,
};

bool is_c_source(std::string_view path);
bool is_cpp_source(std::string_view path);
bool is_interpretable(std::string_view path);
int rand_value();
std::string rand_string(int length);
std::string rand_filename(int length, std::string_view ext = "");
std::string_view home_directory();
std::string main_program();
fs::path must_exist(const fs::path &path);
fs::path convert_file(std::string_view path, std::string_view newext);
int repl_entry(const std::function<void(std::string_view)> &exec);
void iterate_pathenv(
    const std::function<IterateState(std::string_view path)> &callback);

} // namespace icpp
