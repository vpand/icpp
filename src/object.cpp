/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "object.h"
#include <iostream>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBuffer.h>

namespace icpp {

Object::Object(std::string_view path) : path_(path) {}

void Object::createObject(ObjectType type) {
  auto errBuff = llvm::MemoryBuffer::getFile(path_);
  if (!errBuff) {
    std::cout << "Failed to read '" << path_
              << "': " << errBuff.getError().message() << std::endl;
    return;
  }
  auto buffRef = llvm::MemoryBufferRef(*errBuff.get());
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
  } else {
    std::cout << "Failed to create llvm object: "
              << llvm::toString(std::move(expObj.takeError())) << std::endl;
  }
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
