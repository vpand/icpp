/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "runtime.h"
#include "icpp.h"
#include "llvm/Support/MemoryBuffer.h"
#include <isymhash.pb.h>

namespace icpp {

RuntimeLib &RuntimeLib::inst() {
  static RuntimeLib rt;
  return rt;
}

RuntimeLib::RuntimeLib() {}

RuntimeLib::~RuntimeLib() {}

fs::path RuntimeLib::repo(bool force) {
  auto home = fs::path(home_directory()) / repoName;
  return force ? must_exist(home) : home;
}

fs::path RuntimeLib::includeFull() {
  return must_exist(repo() / includeRelative());
}

fs::path RuntimeLib::includeFull(std::string_view module) {
  // .icpp/include/icpp must exist anyway
  return module.size() ? repo() / includeRelative(module)
                       : must_exist(repo() / includeRelative() / includePrefix);
}

fs::path RuntimeLib::libFull() { return must_exist(repo() / libRelative()); }

void RuntimeLib::initHashes() {
  if (hashes_.size())
    return;

  for (auto &entry : fs::recursive_directory_iterator(libFull())) {
    if (entry.is_directory()) {
      auto hashfile = entry.path() / hashFile;
      auto expBuff = llvm::MemoryBuffer::getFile(hashfile.string());
      if (!expBuff)
        continue; // symbol.hash file is missing, ignore this module

      auto buffer = expBuff.get().get();
      auto newit = hashes_
                       .insert({entry.path().filename().string(),
                                std::make_unique<vpimod::SymbolHash>()})
                       .first;
      if (!newit->second->ParseFromArray(buffer->getBufferStart(),
                                         buffer->getBufferSize())) {
        log_print(Runtime, "Failed to parse {}.", hashfile.string());
        continue;
      }
      log_print(Develop, "Loaded symbol hashes from {}.", newit->first);
    }
  }
}

fs::path RuntimeLib::find(std::string_view symbol) {
  auto hash = static_cast<uint32_t>(std::hash<std::string_view>{}(symbol));
  // foreach module
  for (auto &mh : hashes_) {
    // foreach object/library
    for (auto lh : mh.second->hashes()) {
      auto hashbuff = reinterpret_cast<const uint32_t *>(&lh.second[0]);
      if (std::binary_search(hashbuff,
                             hashbuff + lh.second.size() / sizeof(hashbuff[0]),
                             hash)) {
        return libFull(mh.first) / lh.first;
      }
    }
  }
  return "";
}

} // namespace icpp
