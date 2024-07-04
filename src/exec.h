/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <memory>
#include <string_view>
#include <vector>

namespace icpp {

class Object;

// execute with a source file and its relational dependencies
int exec_main(std::string_view path, const std::vector<std::string> &deps,
              std::string_view srcpath, int iargc, char **iargv);

// execute with a small code snippet
void exec_string(const char *argv0, std::string_view snippet,
                 bool whole = false);

// the Read-Evaluate-Print-Loop Implementation of ICPP
int exec_repl(const char *argv0);

// execute the memory loaded object
void exec_object(std::shared_ptr<Object> object);

// execute the dynamically loaded module's constructors
void init_library(std::shared_ptr<Object> imod);

} // namespace icpp
