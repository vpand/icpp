/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include "utils.h"
#include <map>

namespace com {
namespace vpand {
namespace imod {
class SymbolHash;
}
} // namespace vpand
} // namespace com

namespace vpimod = com::vpand::imod;

namespace icpp {

// third-part module extension for icpp runtime, usually it's installed
// by imod package manager
class RuntimeLib {
public:
  static RuntimeLib &inst();

  fs::path repo();
  fs::path includeFull();
  fs::path libFull();

  fs::path includeRelative() { return "include"; }
  fs::path libRelative() { return "lib"; }

  fs::path includeRelative(std::string_view module) {
    return includeRelative() / includePrefix / module;
  }
  fs::path libRelative(std::string_view module) {
    return libRelative() / module;
  }
  fs::path includeFull(std::string_view module);
  fs::path libFull(std::string_view module) {
    return repo() / libRelative(module);
  }

  void initHashes();

  /*
  When module loader can't resolve the symbol, before aborting the whole
  program, it will call this function to check whether user installed modules
  contain the symbol or not. The return value is the located object/library full
  path that contains this symbol.
  */
  fs::path find(std::string_view symbol);

  const std::string_view includePrefix{"icpp"};
  const std::string_view repoName{".icpp"};
  const std::string_view hashFile{"symbol.hash"};
  const std::string_view packageExtension{".icpp"};

private:
  RuntimeLib();
  ~RuntimeLib();

  // <module name, hashes>
  std::map<std::string, std::unique_ptr<vpimod::SymbolHash>> hashes_;
};

} // namespace icpp
