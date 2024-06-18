/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <memory>
#include <string_view>

namespace llvm {
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

enum ArchType {
  Unsupported,
  X86_64,
  AArch64,
};

class Object {
public:
  Object(std::string_view path);
  virtual ~Object();

  bool valid() { return ofile_ != nullptr && arch_ != Unsupported; }

  ObjectType type() { return type_; }

  ArchType arch() { return arch_; }

protected:
  void createObject(ObjectType type);

private:
  ObjectType type_;
  ArchType arch_;
  std::string_view path_;
  std::unique_ptr<CObjectFile> ofile_;
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
