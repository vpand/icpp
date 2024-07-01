/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <cstdint>
#include <string>

#if defined(_WIN32) || defined(_WIN64)
#define __ICPP_EXPORT__ __declspec(dllexport)
#else
#define __ICPP_EXPORT__ __attribute__((visibility("default")))
#endif // end of _WIN

namespace icpp {

// icpp version.
constexpr const std::uint8_t version_major = 0;
constexpr const std::uint8_t version_minor = 0;
constexpr const std::uint8_t version_patch = 1;
// release candidate version, 255 means the official release.
constexpr const std::uint8_t version_extra = 255;

union version_t {
  std::uint32_t value;
  struct {
    std::uint8_t major, minor, patch, extra;
  };
};

std::string version_string();
version_t version_value();

} // namespace icpp
