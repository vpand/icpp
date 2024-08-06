/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "object.h"
#include "utils.h"
#include <llvm/Object/COFF.h>
#include <llvm/Object/ObjectFile.h>

using SymbolRef = llvm::object::SymbolRef;

namespace icpp {

void COFFObject::parseCOFFSymbols() {
  auto coff = static_cast<llvm::object::COFFObjectFile *>(ofile_.get());
  for (auto &exp : coff->export_directories()) {
    uint32_t rva;
    auto err = exp.getExportRVA(rva);
    if (err)
      continue;

    llvm::StringRef name;
    err = exp.getSymbolName(name);
    if (err)
      continue;

    funcs_.insert({name.data(), nullptr});
    if (0) {
      log_print(Develop, "Parsed coff symbol {}.{:x}.", name.data(), rva);
    }
  }
}

} // namespace icpp
