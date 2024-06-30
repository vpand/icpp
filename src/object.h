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
} // namespace object
namespace objdump {
class SourcePrinter;
}
} // namespace llvm

using CObjectFile = llvm::object::ObjectFile;

namespace icpp {

constexpr const uint32_t iobj_magic{'ppci'};
constexpr const std::string_view iobj_ext{".io"};

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
  uint32_t rva;      // instruction file rva

  bool operator<(const InsnInfo &right) const { return rva < right.rva; }
  bool operator==(const InsnInfo &right) const { return rva == right.rva; }
  bool operator>(const InsnInfo &right) const { return rva > right.rva; }
};

struct RelocInfo {
  RelocInfo() = delete;
  RelocInfo(std::string_view n, const void *p, uint32_t t)
      : name(n), target(p), type(t) {}

  // symbol name
  std::string name;
  const void *target; // symbol runtime vm address
  // converted from relocation type
  // e.g.: arm64 GOT reloc ==> ST_DATA, otherwise ST_FUNCTION, etc.
  uint32_t type;
};

struct DynSection {
  std::string name; // section name
  uint32_t rva;     // rva address in object file
  // dynamically allocated buffer for this section, e.g.: bss common
  std::string buffer;
};

struct TextSection {
  // text section index, rva, size and vm values,
  // this kind of section contains instructions
  uint32_t index;
  uint32_t size;
  uint32_t rva; // rva address in object file
  uint64_t vm;  // runtime address in iobject instance
  // instruction informations
  std::vector<InsnInfo> iinfs;
};

class DisassemblerTarget;

struct ObjectDisassembler {
  ObjectDisassembler() {}
  ~ObjectDisassembler();

  void init(CObjectFile *Obj, std::string_view Triple);

  // these classes' definition are unavailable for std::unique_ptr,
  // so raw pointer used, we manage them manually
  DisassemblerTarget *DT = nullptr;
  ::llvm::objdump::SourcePrinter *SP = nullptr;
};

class Object {
public:
  Object(std::string_view srcpath, std::string_view path);
  virtual ~Object();

  constexpr bool valid() { return ofile_ != nullptr && arch_ != Unsupported; }
  constexpr ObjectType type() { return type_; }
  constexpr ArchType arch() { return arch_; }

  constexpr std::string_view path() { return path_; }
  constexpr bool isCache() { return path_.ends_with(iobj_ext); }

  uint64_t vm2rva(uint64_t vm, size_t *ti = nullptr);

  // check whether vm belongs to text section
  bool executable(uint64_t vm, Object **iobject);
  // check whether vm belongs to the whole memory buffer of this object
  virtual bool belong(uint64_t vm, size_t *di = nullptr);
  virtual std::string cachePath();

  const char *triple();
  const void *locateSymbol(std::string_view name, bool data);
  const void *relocTarget(size_t i);

  template <typename T> const T *metaInfo(const InsnInfo *inst, uint64_t vm) {
    auto found =
        idecinfs_.find(std::string(reinterpret_cast<char *>(vm), inst->len));
    assert(found != idecinfs_.end() && "Null meta information is impossiple.");
    return reinterpret_cast<T *>(found->second.data());
  }

  uc_arch ucArch();
  uc_mode ucMode();

  const void *mainEntry();
  std::vector<const void *> ctorEntries();
  std::vector<const void *> dtorEntries();
  const InsnInfo *insnInfo(uint64_t vm);
  std::string sourceInfo(uint64_t vm);
  std::string generateCache();
  void dump();

protected:
  void createObject(ObjectType type);
  void parseSymbols();
  void parseSections();
  void decodeInsns(TextSection &text);
  void decodeInsns() {
    for (auto &s : textsects_)
      decodeInsns(s);
  }

protected:
  ObjectDisassembler odiser_;
  ObjectType type_;
  ArchType arch_;
  std::string srcpath_;
  std::string path_;
  std::unique_ptr<::llvm::MemoryBuffer> fbuf_;
  std::unique_ptr<CObjectFile> ofile_;
  // <entry name, opcodes pointer>
  std::unordered_map<std::string, const void *> funcs_;
  // <data name, data pointer>
  std::unordered_map<std::string, const void *> datas_;
  // text sections
  std::vector<TextSection> textsects_;
  // dynamically allocated sections
  std::vector<DynSection> dynsects_;
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

class InterpObject : public Object {
public:
  InterpObject(std::string_view srcpath, std::string_view path);
  virtual ~InterpObject();

  bool belong(uint64_t vm, size_t *di) override;
  std::string cachePath() override { return path_; }

private:
  std::string ofbuf_; // .o file buffer copied from .io file
};

} // namespace icpp
