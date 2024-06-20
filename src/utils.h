/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <filesystem>
#include <iostream>
#include <string_view>

namespace fs = std::filesystem;

#define UNIMPL_ABORT()                                                         \
  {                                                                            \
    std::cout << "Un-implement " << __FUNCTION__ << " currently yet."          \
              << std::endl;                                                    \
    abort();                                                                   \
  }

namespace icpp {

bool is_cpp_source(std::string_view path);
int rand_value();
std::string rand_string(int length);
std::string rand_filename(int length, std::string_view ext = "");

} // namespace icpp
