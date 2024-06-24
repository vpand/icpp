/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "utils.h"
#include <array>
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

} // namespace icpp
