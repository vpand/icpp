/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include "arch.h"
#include <cassert>
#include <map>
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

static const uint32_t iobj_magic = 'ppci';
static const char *iobj_ext = ".io";

enum ObjectType {
  MachO_Reloc,
  MachO_Exe,
  ELF_Reloc,
  ELF_Exe,
  COFF_Reloc,
  COFF_Exe,
};

struct InsnInfo {
  uint32_t type : 8, // instruction type
      len : 5,       // opcode length
      rflag : 1,     // relocation flag, 1 indicates a valid reloc index
      reloc : 18;    // relocation index
  uint32_t rva;      // instruction rva

  bool operator<(const InsnInfo &right) const { return rva < right.rva; }
  bool operator==(const InsnInfo &right) const { return rva == right.rva; }
  bool operator>(const InsnInfo &right) const { return rva > right.rva; }
};

struct RelocInfo {
  // symbol name
  std::string name;
  const void *target; // symbol runtime vm address
};

struct DynSection {
  std::string name; // section name
  uint64_t rva;     // address in file
  // dynamically allocated buffer for this section, e.g.: bss common
  std::string buffer;
};

class Object {
public:
  Object(std::string_view srcpath, std::string_view path);
  virtual ~Object();

  constexpr bool valid() { return ofile_ != nullptr && arch_ != Unsupported; }

  constexpr ObjectType type() { return type_; }

  constexpr ArchType arch() { return arch_; }

  constexpr bool cover(uint64_t vm) {
    return textvm_ <= vm && vm < textvm_ + textsz_;
  }

  const char *triple();

  constexpr const void *relocTarget(size_t i) { return irelocs_[i].target; }

  template <typename T> const T *metaInfo(const InsnInfo *inst, uint64_t vm) {
    auto found =
        idecinfs_.find(std::string(reinterpret_cast<char *>(vm), inst->len));
    assert(found != idecinfs_.end() && "Null meta information is impossiple.");
    return reinterpret_cast<T *>(found->second.data());
  }

  constexpr uint64_t vm2rva(uint64_t vm) { return textrva_ + vm - textvm_; }

  uc_arch ucArch();
  uc_mode ucMode();

  const void *mainEntry();
  const InsnInfo *insnInfo(uint64_t vm);
  std::string sourceInfo(uint64_t vm);
  std::string generateCache();

protected:
  void createObject(ObjectType type);
  void parseSymbols();
  void parseSections();
  void decodeInsns();
  std::string_view textSectName();

private:
  ObjectType type_;
  ArchType arch_;
  std::string_view srcpath_;
  std::string_view path_;
  std::unique_ptr<llvm::MemoryBuffer> fbuf_;
  std::unique_ptr<CObjectFile> ofile_;
  // <entry name, opcodes pointer>
  std::unordered_map<std::string_view, const void *> funcs_;
  // <data name, data pointer>
  std::unordered_map<std::string_view, const void *> datas_;
  // text section index, rva, size and vm values
  uint32_t textsecti_ = 0;
  uint32_t textsz_ = 0;
  uint64_t textrva_ = 0;
  uint64_t textvm_ = 0;
  // dynamically allocated sections
  std::vector<DynSection> dynsects_;
  // instruction informations
  std::vector<InsnInfo> iinfs_;
  // instruction decoded informations from machine opcode
  // <opcodes, decodes>
  std::map<std::string, std::string> idecinfs_;
  // instruction relocations
  std::vector<RelocInfo> irelocs_;
};

class MachOObject : public Object {
public:
  MachOObject(std::string_view srcpath, std::string_view path);
  virtual ~MachOObject();
};

class MachORelocObject : public MachOObject {
public:
  MachORelocObject(std::string_view srcpath, std::string_view path);
  virtual ~MachORelocObject();
};

class MachOExeObject : public MachOObject {
public:
  MachOExeObject(std::string_view srcpath, std::string_view path);
  virtual ~MachOExeObject();
};

class ELFObject : public Object {
public:
  ELFObject(std::string_view srcpath, std::string_view path);
  virtual ~ELFObject();
};

class ELFRelocObject : public ELFObject {
public:
  ELFRelocObject(std::string_view srcpath, std::string_view path);
  virtual ~ELFRelocObject();
};

class ELFExeObject : public ELFObject {
public:
  ELFExeObject(std::string_view srcpath, std::string_view path);
  virtual ~ELFExeObject();
};

class COFFObject : public Object {
public:
  COFFObject(std::string_view srcpath, std::string_view path);
  virtual ~COFFObject();
};

class COFFRelocObject : public COFFObject {
public:
  COFFRelocObject(std::string_view srcpath, std::string_view path);
  virtual ~COFFRelocObject();
};

class COFFExeObject : public COFFObject {
public:
  COFFExeObject(std::string_view srcpath, std::string_view path);
  virtual ~COFFExeObject();
};

} // namespace icpp
