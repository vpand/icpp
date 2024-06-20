/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include "utils.h"

namespace icpp {

fs::path compile_source(const char *argv0, std::string_view path,
                        const char *opt,
                        const std::vector<const char *> &incdirs);

}
