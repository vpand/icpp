/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include "log.h"
#include <filesystem>
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

bool is_cpp_source(std::string_view path);
int rand_value();
std::string rand_string(int length);
std::string rand_filename(int length, std::string_view ext = "");

} // namespace icpp
