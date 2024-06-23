/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <cstdint>

// functions for lldb debug shell
extern "C" {}

namespace icpp {

constexpr int dbgport = 24623; // defined on date 2024.6.23

struct ProtocolHdr {
  std::uint32_t cmd : 8, // command id
      len : 24;          // protobuf length
};

} // namespace icpp
