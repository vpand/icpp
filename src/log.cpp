/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

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
