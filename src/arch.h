/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

namespace icpp {

enum ArchType {
  Unsupported,
  X86_64,
  AArch64,
};

ArchType host_arch();

} // namespace icpp