/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace icpp {

class Object;

class Loader {
public:
  Loader(Object *object, const std::vector<std::string> &deps);
  ~Loader();

  bool valid();

  // locate the symbol runtime address
  static const void *locateSymbol(std::string_view name, bool data);

  // locate the module path which the symbol belongs to
  static std::string_view locateModule(const void *addr, bool update = false);

private:
  Object *object_;
};

} // namespace icpp
