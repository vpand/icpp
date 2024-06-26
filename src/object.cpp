/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "object.h"
#include "utils.h"
#include <iostream>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBuffer.h>

namespace icpp {

Object::Object(std::string_view path) : path_(path) {}

const char *Object::triple() {
  switch (type_) {
  case ELF_Reloc:
  case ELF_Exe:
    switch (arch_) {
    case AArch64:
      return "aarch64-none-linux-android";
    case X86_64:
      return "x86_64-none-linux-android";
    default:
      return "";
    }
  case MachO_Reloc:
  case MachO_Exe:
    switch (arch_) {
    case AArch64:
      return "arm64-apple-macosx";
    case X86_64:
      return "x86_64-apple-macosx";
    default:
      return "";
    }
  case COFF_Reloc:
  case COFF_Exe:
    switch (arch_) {
    case X86_64:
      return "x86_64-pc-windows-msvc";
    default:
      return "";
    }
  default:
    return "";
  }
}

void Object::createObject(ObjectType type) {
  // herein we pass IsVolatile as true to disable llvm to mmap this file
  // because some data sections may be modified at runtime
  auto errBuff = llvm::MemoryBuffer::getFile(path_, false, true, true);
  if (!errBuff) {
    std::cout << "Failed to read '" << path_
              << "': " << errBuff.getError().message() << std::endl;
    return;
  }
  fbuf_ = std::move(errBuff.get());
  auto buffRef = llvm::MemoryBufferRef(*fbuf_);
  auto expObj = CObjectFile::createObjectFile(buffRef);
  if (expObj) {
    type_ = type;
    ofile_ = std::move(expObj.get());
    switch (ofile_->getArch()) {
    case llvm::Triple::aarch64:
      arch_ = AArch64;
      break;
    case llvm::Triple::x86_64:
      arch_ = X86_64;
      break;
    default:
      arch_ = Unsupported;
      break;
    }
    parseSections();
    parseSymbols();
    decodeInsns();
  } else {
    std::cout << "Failed to create llvm object: "
              << llvm::toString(std::move(expObj.takeError())) << std::endl;
  }
}

void Object::parseSymbols() {
  using SymbolRef = llvm::object::SymbolRef;
  for (auto sym : ofile_->symbols()) {
    auto expType = sym.getType();
    if (!expType)
      continue;
    std::unordered_map<std::string_view, const void *> *caches = nullptr;
    switch (expType.get()) {
    case SymbolRef::ST_Data:
      caches = &datas_;
      break;
    case SymbolRef::ST_Function:
      caches = &funcs_;
      break;
    default:
      break;
    }
    if (!caches)
      continue;
    auto expFlags = sym.getFlags();
    if (!expFlags)
      continue;
    auto flags = expFlags.get();
    if ((flags & SymbolRef::SF_Undefined) || (flags & SymbolRef::SF_Common) ||
        (flags & SymbolRef::SF_Indirect) ||
        (flags & SymbolRef::SF_FormatSpecific)) {
      continue;
    }
    auto expSect = sym.getSection();
    auto expAddr = sym.getAddress();
    auto expName = sym.getName();
    if (!expSect || !expAddr || !expName)
      continue;
    auto sect = expSect.get();
    auto expSContent = sect->getContents();
    if (!expSContent)
      continue;
    auto saddr = sect->getAddress();
    auto sbuff = expSContent.get();
    auto snameExp = sect->getName();
    if (!snameExp)
      continue;
    auto addr = expAddr.get();
    auto name = expName.get();
    auto buff = sbuff.data() + addr - saddr;
    for (auto &ds : dynsects_) {
      if (snameExp.get() == ds.name) {
        // dynamically allocated section
        buff = ds.buffer.data() + addr - saddr;
        break;
      }
    }
    // ignore the internal temporary symbols
    if (name.starts_with("ltmp") || name.starts_with("l_."))
      continue;
    caches->insert({name.data(), buff});
    log_print(Develop, "Cached symbol {}.{},{}.", name.data(),
              static_cast<const void *>(name.data()),
              static_cast<const void *>(buff));
  }
}

std::string_view Object::textSectName() {
  std::string_view textname(".text");
  if (ofile_->isMachO()) {
    textname = "__text";
  }
  return textname;
}

void Object::parseSections() {
  auto textname = textSectName();
  textsecti_ = 0;
  for (auto &s : ofile_->sections()) {
    auto expName = s.getName();
    if (!expName) {
      if (!textsz_)
        textsecti_++;
      continue;
    }

    auto name = expName.get();
    if (textname == name.data()) {
      auto expContent = s.getContents();
      if (!expContent) {
        log_print(Runtime, "Empty object file, there's no {} section.",
                  textname);
        break;
      }
      textsz_ = s.getSize();
      textrva_ = s.getAddress();
      textvm_ = reinterpret_cast<uint64_t>(expContent->data());
      log_print(Develop, "Text rva={:x}, vm={:x}.", textrva_, textvm_);
    } else if (name.ends_with("bss") || name.ends_with("common")) {
      dynsects_.push_back(
          {name.data(), s.getAddress(), std::string(s.getSize(), 0)});
    }

    if (!textsz_)
      textsecti_++;
  }
}

uc_arch Object::ucArch() {
  switch (arch_) {
  case AArch64:
    return UC_ARCH_ARM64;
  case X86_64:
    return UC_ARCH_X86;
  default:
    return UC_ARCH_MAX; // unsupported
  }
}

uc_mode Object::ucMode() {
  switch (arch_) {
  case X86_64:
    return UC_MODE_64;
  default:
    return UC_MODE_LITTLE_ENDIAN;
  }
}

const void *Object::mainEntry() {
  auto found = funcs_.find("_main");
  if (found == funcs_.end()) {
    found = funcs_.find("main");
  }
  if (found == funcs_.end()) {
    return nullptr;
  }
  return found->second;
}

const InsnInfo *Object::insnInfo(uint64_t vm) {
  auto rva = static_cast<uint32_t>(vm2rva(vm));
  // find insninfo related to this vm address
  auto found =
      std::lower_bound(iinfs_.begin(), iinfs_.end(), InsnInfo{.rva = rva});
  if (found == iinfs_.end()) {
    log_print(Runtime, "Failed to find instruction information of rva {:x}.",
              rva);
    abort();
  }
  return &*found;
}

Object::~Object() {}

MachOObject::MachOObject(std::string_view path) : Object(path) {}

MachOObject::~MachOObject() {}

MachORelocObject::MachORelocObject(std::string_view path) : MachOObject(path) {
  createObject(MachO_Reloc);
}

MachORelocObject::~MachORelocObject() {}

MachOExeObject::MachOExeObject(std::string_view path) : MachOObject(path) {
  createObject(MachO_Exe);
}

MachOExeObject::~MachOExeObject() {}

ELFObject::ELFObject(std::string_view path) : Object(path) {}

ELFObject::~ELFObject() {}

ELFRelocObject::ELFRelocObject(std::string_view path) : ELFObject(path) {
  createObject(ELF_Reloc);
}

ELFRelocObject::~ELFRelocObject() {}

ELFExeObject::ELFExeObject(std::string_view path) : ELFObject(path) {
  createObject(ELF_Exe);
}

ELFExeObject::~ELFExeObject() {}

COFFObject::COFFObject(std::string_view path) : Object(path) {}

COFFObject::~COFFObject() {}

COFFRelocObject::COFFRelocObject(std::string_view path) : COFFObject(path) {
  createObject(COFF_Reloc);
}

COFFRelocObject::~COFFRelocObject() {}

COFFExeObject::COFFExeObject(std::string_view path) : COFFObject(path) {
  createObject(COFF_Exe);
}

COFFExeObject::~COFFExeObject() {}

} // namespace icpp
