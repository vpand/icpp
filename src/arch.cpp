/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "arch.h"

namespace icpp {

ArchType host_arch() {
#if __arm64__ || __aarch64__
  return AArch64;
#elif __x86_64__ || __x64__
  return X86_64;
#else
#error Unsupported host architecture.
#endif
}

} // namespace icpp