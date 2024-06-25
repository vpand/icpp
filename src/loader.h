/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
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

  static const void *locateSymbol(std::string_view name, bool data);

private:
  Object *object_;
};

} // namespace icpp
