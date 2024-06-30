/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "runcfg.h"
#include <memory>

namespace icpp {

bool RunConfig::repl = false;

RunConfig *RunConfig::inst(const char *cfg) {
  static std::unique_ptr<RunConfig> runcfg;
  if (runcfg)
    return runcfg.get();
  if (!cfg)
    return nullptr;
  runcfg = std::make_unique<RunConfig>(cfg);
  return runcfg.get();
}

RunConfig::RunConfig(const char *cfg) {}

RunConfig::~RunConfig() {}

int RunConfig::stackSize() { return 1024 * 1024; }

int RunConfig::stepSize() { return 1; }

bool RunConfig::hasDebugger() { return false; }

} // namespace icpp
