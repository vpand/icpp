/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "icpp.h"
#include <format>

namespace icpp {

std::string version_string() {
  return std::format("v{}.{}.{}.{}", version_major, version_minor,
                     version_patch, version_extra);
}

version_t version_value() {
  return version_t{.major = version_major,
                   .minor = version_minor,
                   .patch = version_patch,
                   .extra = version_extra};
}

} // namespace icpp
