/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "loader.h"
#include "object.h"

namespace icpp {

Loader::Loader(Object *object, const std::vector<std::string> &deps)
    : object_(object) {}

Loader::~Loader() {}

bool Loader::valid() { return true; }

const void *Loader::locateSymbol(std::string_view name, bool data) {
  return nullptr;
}

} // namespace icpp
