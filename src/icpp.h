/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <cstdint>
#include <string>

namespace icpp {

// icpp version.
const std::uint8_t version_major = 0;
const std::uint8_t version_minor = 0;
const std::uint8_t version_patch = 1;
// release candidate version, 255 means the official release.
const std::uint8_t version_extra = 255;

union version_t {
  std::uint32_t value;
  struct {
    std::uint8_t major, minor, patch, extra;
  };
};

std::string version_string();
version_t version_value();

} // namespace icpp
