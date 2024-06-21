/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include "arch.h"
#include <memory>
#include <string_view>
#include <unicorn/unicorn.h>
#include <unordered_map>

namespace llvm {
class MemoryBuffer;
namespace object {
class ObjectFile;
}
} // namespace llvm

using CObjectFile = llvm::object::ObjectFile;

namespace icpp {

enum ObjectType {
  MachO_Reloc,
  MachO_Exe,
  ELF_Reloc,
  ELF_Exe,
  COFF_Reloc,
  COFF_Exe,
};

class Object {
public:
  Object(std::string_view path);
  virtual ~Object();

  constexpr bool valid() { return ofile_ != nullptr && arch_ != Unsupported; }

  constexpr ObjectType type() { return type_; }

  constexpr ArchType arch() { return arch_; }

  uc_arch ucArch();
  uc_mode ucMode();

  const void *mainEntry();

protected:
  void createObject(ObjectType type);
  void parseSymbols();

private:
  ObjectType type_;
  ArchType arch_;
  std::string_view path_;
  std::unique_ptr<llvm::MemoryBuffer> fbuf_;
  std::unique_ptr<CObjectFile> ofile_;
  // <entry name, opcodes pointer>
  std::unordered_map<std::string_view, const void *> funcs_;
  // <data name, data pointer>
  std::unordered_map<std::string_view, const void *> datas_;
};

class MachOObject : public Object {
public:
  MachOObject(std::string_view path);
  virtual ~MachOObject();
};

class MachORelocObject : public MachOObject {
public:
  MachORelocObject(std::string_view path);
  virtual ~MachORelocObject();
};

class MachOExeObject : public MachOObject {
public:
  MachOExeObject(std::string_view path);
  virtual ~MachOExeObject();
};

class ELFObject : public Object {
public:
  ELFObject(std::string_view path);
  virtual ~ELFObject();
};

class ELFRelocObject : public ELFObject {
public:
  ELFRelocObject(std::string_view path);
  virtual ~ELFRelocObject();
};

class ELFExeObject : public ELFObject {
public:
  ELFExeObject(std::string_view path);
  virtual ~ELFExeObject();
};

class COFFObject : public Object {
public:
  COFFObject(std::string_view path);
  virtual ~COFFObject();
};

class COFFRelocObject : public COFFObject {
public:
  COFFRelocObject(std::string_view path);
  virtual ~COFFRelocObject();
};

class COFFExeObject : public COFFObject {
public:
  COFFExeObject(std::string_view path);
  virtual ~COFFExeObject();
};

} // namespace icpp
