/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "runcfg.h"

namespace icpp {

RunConfig::RunConfig(const char *cfg) {}

RunConfig::~RunConfig() {}

int RunConfig::stackSize() { return 1024 * 1024; }

int RunConfig::stepSize() { return 1; }

} // namespace icpp
