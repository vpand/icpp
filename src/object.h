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
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace llvm {
class MemoryBuffer;
class StringRef;
namespace object {
class ObjectFile;
} // namespace object
namespace objdump {
class SourcePrinter;
}
} // namespace llvm

using CObjectFile = llvm::object::ObjectFile;

namespace icpp {

constexpr const uint32_t iobj_magic{'jboi'};
constexpr const std::string_view iobj_ext{".io"};
constexpr const std::string_view obj_ext{".o"};

struct InsnInfo {
  uint32_t type : 8, // instruction type
      len : 5,       // opcode length
      rflag : 1,     // relocation flag, 1 indicates a valid reloc index
      reloc : 18;    // relocation index
  uint32_t rva;      // instruction vm address rva

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

  const void *realTarget();
};

struct DynSection {
  uint32_t index; // section index
  // dynamically allocated buffer for this section, e.g.: bss common
  std::string buffer;
};

struct TextSection {
  // text section index, rva, size and vm values,
  // this kind of section contains instructions
  uint32_t index;
  uint32_t size;
  uint32_t frva;  // file buffer rva from .text[0]
  uint64_t vmrva; // vm address rva like in VMPStudio or IDA
  uint64_t vm;    // runtime address in iobject instance
  // instruction informations
  std::vector<InsnInfo> iinfs;
};

struct StubSpot {
  uint32_t index;        // section index
  uint32_t offset;       // offset in this section
  uint64_t vm;           // vm address
  std::string_view name; // symbol name
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
  constexpr uint64_t vm2rvaSimple(uint64_t vm) {
    return vm - textsects_[0].vm;
  };

  constexpr std::vector<StubSpot> &stubSpots() { return stubspots_; }

  uint64_t vm2rva(uint64_t vm, size_t *ti = nullptr);

  // check whether vm belongs to text section
  bool executable(uint64_t vm, Object **iobject);
  // check whether vm belongs to the whole memory buffer of this object
  virtual bool belong(uint64_t vm, size_t *di = nullptr);
  virtual std::string cachePath();

  const char *triple();
  const void *locateSymbol(std::string_view name);
  const void *relocTarget(size_t i);

  template <typename T> const T *metaInfo(const InsnInfo *inst, uint64_t vm) {
    auto found =
        idecinfs_.find(std::string(reinterpret_cast<char *>(vm), inst->len));
    assert(found != idecinfs_.end() && "Null meta information is impossiple.");
    return reinterpret_cast<T *>(found->second.data());
  }

  const void *mainEntry();
  std::vector<const void *> ctorEntries();
  std::vector<const void *> dtorEntries();
  const InsnInfo *insnInfo(uint64_t vm);
  std::string sourceInfo(uint64_t vm);
  std::string generateCache();
  void dump();

protected:
  void createFromMemory(ObjectType type);
  void createFromFile(ObjectType type);
  void parseSymbols();
  void parseSections();
  void decodeInsns(TextSection &text);
  void decodeInsns() {
    for (auto &s : textsects_)
      decodeInsns(s);
  }

  void relocateData(uint32_t index, const llvm::StringRef &content,
                    uint64_t offset, const void *rsym);

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
  // data section spots which contain pointer in text section,
  // they'll be redirect to dynamic stub created by ExecEngine
  std::vector<StubSpot> stubspots_;
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

class MachOMemoryObject : public MachOObject {
public:
  MachOMemoryObject(std::string_view name,
                    std::unique_ptr<::llvm::MemoryBuffer> memobj);
  virtual ~MachOMemoryObject();
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

class ELFMemoryObject : public ELFObject {
public:
  ELFMemoryObject(std::string_view name,
                  std::unique_ptr<::llvm::MemoryBuffer> memobj);
  virtual ~ELFMemoryObject();
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

class COFFMemoryObject : public COFFObject {
public:
  COFFMemoryObject(std::string_view name,
                   std::unique_ptr<::llvm::MemoryBuffer> memobj);
  virtual ~COFFMemoryObject();
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

class SymbolHash : public Object {
public:
  SymbolHash(std::string_view path);
  virtual ~SymbolHash();

  std::vector<uint32_t> hashes(std::string &message);
};

std::shared_ptr<Object> create_object(std::string_view srcpath,
                                      std::string_view path, bool &validcache);

} // namespace icpp
