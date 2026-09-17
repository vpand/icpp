// Interpreting C++(ICPP) - Run C++ anywhere, just like a script.
// Copyright (c) 2026 Jesse Liu <neoliu2011@gmail.com>
// SPDX-License-Identifier: Apache License, Version 2.0
// See LICENSE file in the root directory for full license text.

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
