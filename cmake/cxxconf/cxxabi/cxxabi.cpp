/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2026 */
/* Copyright (c) vpand.com 2026. This file is released under GPLv2.
   See LICENSE in root directory for more details
*/

namespace std {

using unexpected_handler = void (*)();
using terminate_handler = void (*)();
using new_handler = void (*)();

unexpected_handler set_unexpected(unexpected_handler func) noexcept {
  return nullptr;
}

terminate_handler set_terminate(terminate_handler func) noexcept {
  return nullptr;
}

new_handler set_new_handler(new_handler handler) noexcept { return nullptr; }

} // namespace std
