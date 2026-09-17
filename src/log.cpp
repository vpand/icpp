// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

#include "log.h"
#include "platform.h"

namespace icpp {

log_writer_func_t log_writer = nullptr;

}

/*
Install a user defined log writer function, e.g. for GUI application
*/
extern "C" __ICPP_EXPORT__ icpp::log_writer_func_t
icpp_logger(icpp::log_writer_func_t writer) {
  auto old = icpp::log_writer;
  if (writer)
    icpp::log_writer = writer;
  return old;
}
