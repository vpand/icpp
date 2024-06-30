/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <memory.h>
#include <string_view>
#include <vector>

namespace icpp {

class Object;

void exec_main(std::string_view path, const std::vector<std::string> &deps,
               std::string_view srcpath, int iargc, char **iargv);

void init_library(std::shared_ptr<Object> imod);

} // namespace icpp
