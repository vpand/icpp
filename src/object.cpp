/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "object.h"
#include "icpp.h"
#include "loader.h"
#include "platform.h"
#include "runcfg.h"
#include "utils.h"
#include <boost/beast.hpp>
#include <fstream>
#include <icppiobj.pb.h>
#include <iostream>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBuffer.h>
#include <span>

using CSymbolRef = llvm::object::SymbolRef;

namespace icpp {

Object::Object(std::string_view srcpath, std::string_view path)
    : srcpath_(srcpath), path_(path) {
  // lazy initialization of the module/object loader
  Loader::initialize();

  if (!srcpath_.length())
    srcpath_ = path_;

  if (RunConfig::gadget)
    return;

  srcpath_ = fs::absolute(srcpath_).string();
  path_ = fs::absolute(path_).string();
}

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

void Object::createFromMemory(ObjectType type) {
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
    odiser_.init(ofile_.get(), triple());
    parseSections();
    parseSymbols();
    decodeInsns();
  } else {
    std::cout << "Failed to create llvm object: "
              << llvm::toString(std::move(expObj.takeError())) << std::endl;
  }
}

void Object::createFromFile(ObjectType type) {
  switch (type) {
  case COFF_Exe:
  case ELF_Exe:
  case MachO_Exe:
    log_print(
        Runtime,
        "The current version of icpp doesn't support running executable yet.");
    return;
  default:
    break;
  }

  // herein we pass IsVolatile as true to disable llvm to mmap this file
  // because some data sections may be modified at runtime
  auto errBuff = llvm::MemoryBuffer::getFile(path_, false, true, true);
  if (!errBuff) {
    std::cout << "Failed to read '" << path_
              << "': " << errBuff.getError().message() << std::endl;
    return;
  }
  fbuf_ = std::move(errBuff.get());
  createFromMemory(type);
}

void Object::parseSymbols() {
  using SymbolRef = CSymbolRef;
  for (auto sym : ofile_->symbols()) {
    auto expType = sym.getType();
    if (!expType)
      continue;
    std::unordered_map<std::string, const void *> *caches = nullptr;
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
    if (0) {
      log_print(Develop, "Cached symbol {}.{:x}.{}.", name.data(), addr,
                static_cast<const void *>(buff));
    }
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

static std::vector<const void *>
cdtor_entries(CObjectFile *ofile, const std::span<std::string_view> &names,
              const std::unordered_map<std::string, const void *> &funcs,
              bool ctor) {
  std::vector<const void *> results;
  for (auto &s : ofile->sections()) {
    auto expName = s.getName();
    if (!expName)
      continue;
    // elf startup section on object file
    if (ctor && *expName == ".text.startup") {
      auto expContent = s.getContents();
      if (expContent) {
        results.push_back(expContent->data());
      }
      continue;
    }
    for (auto sn : names) {
      if (expName->contains(sn)) {
        for (auto &r : s.relocations()) {
          auto sym = r.getSymbol();
          auto symName = sym->getName();
          if (!symName)
            continue;
          auto found = funcs.find(symName->data());
          if (found != funcs.end())
            results.push_back(found->second);
          else
            log_print(Develop,
                      "Warning, failed to locate constructor function {}.",
                      symName->data());
        }
      }
    }
  }
  return results;
}

std::vector<const void *> Object::ctorEntries() {
  std::string_view names[] = {"init_func", "CRT$XCU"};
  std::span sns{names, std::size(names)};
  auto ctors = cdtor_entries(ofile_.get(), sns, funcs_, true);
  for (auto it = ctors.begin(); it != ctors.end();) {
    auto inst = insnInfo(reinterpret_cast<uint64_t>(*it));
    if (inst->rflag) {
      auto &reloc = irelocs_[inst->reloc];
      if (reloc.name.find(cppm_init_func) != std::string::npos) {
        // remove the cpp module initializer nop function
        it = ctors.erase(it);
        continue;
      }
    }
    it++;
  }
  return ctors;
}

std::vector<const void *> Object::dtorEntries() {
  std::string_view names[] = {"term_func"};
  std::span sns{names, std::size(names)};
  return cdtor_entries(ofile_.get(), sns, funcs_, false);
}

const InsnInfo *Object::insnInfo(uint64_t vm) {
  size_t ti;
  auto rva = static_cast<uint32_t>(vm2rva(vm, &ti));
  // find insninfo related to this vm address
  auto &ts = textsects_[ti];
  auto found =
      std::lower_bound(ts.iinfs.begin(), ts.iinfs.end(), InsnInfo{.rva = rva});
  if (found == ts.iinfs.end()) {
    log_print(Runtime, "Failed to find instruction information of rva {:x}.",
              rva);
    abort();
  }
  return &*found;
}

uint64_t Object::vm2rva(uint64_t vm, size_t *ti) {
  for (size_t i = 0; i < textsects_.size(); i++) {
    auto &s = textsects_[i];
    if (s.vm <= vm && vm < s.vm + s.size) {
      if (ti) {
        ti[0] = i;
      }
      return s.rva + vm - s.vm;
    }
  }
  for (auto &s : ofile_->sections()) {
    if (s.isBSS())
      continue;
    auto expContent = s.getContents();
    if (!expContent)
      continue;
    auto start = reinterpret_cast<uint64_t>(expContent->data());
    if (!start)
      continue;
    if (start <= vm && vm < start + s.getSize()) {
      if (ti) {
        log_print(Runtime, "Logical error, if vm belongs to some data section, "
                           "then ti must be nullptr.");
        abort();
      }
      // return rva to text section
      return textsects_[0].rva + vm - textsects_[0].vm;
    }
  }
  return -1;
}

bool Object::executable(uint64_t vm, Object **iobject) {
  if (vm2rva(vm) != -1) {
    if (iobject)
      iobject[0] = this;
    return true;
  }
  if (!iobject)
    return false;
  return Loader::executable(vm, iobject);
}

std::string Object::cachePath() {
  auto srcpath = fs::path(srcpath_);
  return (srcpath.parent_path() / (srcpath.stem().string() + iobj_ext.data()))
      .string();
}

bool Object::belong(uint64_t vm, size_t *di) {
  auto ptr = reinterpret_cast<const char *>(vm);
  // in object file buffer
  if (fbuf_->getBufferStart() <= ptr && ptr < fbuf_->getBufferEnd())
    return true;
  // in dynamically allocated section, .e.g.: bss
  for (auto &s : dynsects_) {
    if (s.buffer.data() <= ptr && ptr < s.buffer.data() + s.buffer.size()) {
      if (di) {
        di[0] = &s - &dynsects_[0];
      }
      return true;
    }
  }
  return false;
}

const void *RelocInfo::realTarget() {
  return type == CSymbolRef::ST_Data
             ? *reinterpret_cast<void **>(const_cast<void *>(target))
             : target;
}

std::string Object::generateCache() {
  namespace iobj = com::vpand::icppiobj;
  namespace base64 = boost::beast::detail::base64;

  // construct the iobj file
  iobj::InterpObject iobject;
  iobject.set_magic(iobj_magic);
  iobject.set_version(version_value().value);
  iobject.set_arch(static_cast<iobj::ArchType>(arch_));
  iobject.set_otype(static_cast<iobj::ObjectType>(type_));

  auto iins = iobject.mutable_instinfos();
  for (auto &ts : textsects_) {
    iobj::InsnInfos iinfos;
    auto infos = iinfos.mutable_infos();
    infos->Resize(ts.iinfs.size(), 0);
    std::memcpy(infos->mutable_data(), &ts.iinfs[0],
                ts.iinfs.size() * sizeof(uint64_t));
    iins->Add(std::move(iinfos));
  }

  auto imetas = iobject.mutable_instmetas();
  for (auto &m : idecinfs_) {
    // as we use string as protobuf's map key, so we have to encode it as a real
    // string, otherwise its serialization will warn
    auto keysz = base64::encoded_size(m.first.length());
    std::string tmpkey(keysz, '\0');
    keysz = base64::encode(
        reinterpret_cast<void *>(const_cast<char *>(tmpkey.data())),
        m.first.data(), m.first.length());
    imetas->insert({std::string(tmpkey.data(), keysz), m.second});
  }

  auto imods = iobject.mutable_modules();
  auto irefs = iobject.mutable_irefsyms();
  std::set<std::string> refmods;
  Loader::locateModule("", true); // update loader's module list
  for (auto &r : irelocs_) {
    // collect referenced modules
    if (!belong(reinterpret_cast<uint64_t>(r.realTarget())) &&
        !belong(reinterpret_cast<uint64_t>(r.target))) {
      refmods.insert(Loader::locateModule(r.realTarget()).data());
    }
  }
  imods->Add("self");
  for (auto &m : refmods) {
    imods->Add(m.data());
  }
  for (auto &r : irelocs_) {
    auto target = reinterpret_cast<uint64_t>(r.target);
    size_t di = -1;
    bool self = belong(target, &di);

    iobj::RelocInfo ri;
    ri.set_symbol(r.name);
    ri.set_type(r.type);

    if (self) {
      if (di != -1) {
        // it's in dynamical section
        ri.set_dindex(static_cast<uint32_t>(di));
        ri.set_rva(reinterpret_cast<const char *>(target) -
                   dynsects_[di].buffer.data());
      } else {
        ri.set_dindex(-1);
        ri.set_rva(vm2rva(target));
      }
      ri.set_module(0); // set self module index
    } else {
      ri.set_dindex(-1);
      ri.set_rva(-1);
      auto tarmod = Loader::locateModule(r.realTarget());
      for (size_t i = 1; i < imods->size(); i++) {
        if (imods->at(i) == tarmod) {
          // set external module index
          ri.set_module(i);
          break;
        }
      }
    }
    irefs->Add(std::move(ri));
  }

  // set the original object buffer
  iobject.set_objbuf(
      std::string(fbuf_.get()->getBufferStart(), fbuf_.get()->getBufferSize()));

  // save to io file
  auto cachepath = cachePath();
  std::ofstream fout(cachepath, std::ios::binary);
  if (fout.is_open()) {
    iobject.SerializeToOstream(&fout);
    log_print(Develop, "Cached the interpretable object {}.", cachepath);
    return path_;
  } else {
    log_print(Runtime, "Failed to create interpretable object {}: {}.",
              cachepath, std::strerror(errno));
    return "";
  }
}

const void *Object::locateSymbol(std::string_view name) {
  // symbol finder
  auto finder = []<typename T>(const T &conts,
                               const std::string &sym) -> const void * {
    auto fit = conts.find(sym);
    if (fit != conts.end())
      return fit->second;
    return nullptr;
  };
  std::string sym(name.data());
  // find in function list
  auto target = finder(funcs_, sym);
  if (target)
    return target;
  // find in data list
  return finder(datas_, sym);
}

void Object::dump() {
  log_print(Raw, "IObject({}) Details:", path_);

#if 0
  log_print(Raw, "Relocations:");
  for (auto &r : irelocs_) {
    auto target = reinterpret_cast<uint64_t>(r.target);
    if (belong(target))
      log_print(Raw, "SELF - {}.{:x} type.{}", r.name, vm2rva(target), r.type);
    else
      log_print(Raw, "EXTN - {}.{:x} type.{}", r.name, target, r.type);
  }
#endif

  log_print(Raw, "");
}

const void *Object::relocTarget(size_t i) {
  auto cur = &irelocs_[i];
  if (cur->type == CSymbolRef::ST_Data) {
    // herein we must return a pointer-to-pointer if this relocation type
    // references a data type target, usually, it's a kind of GOT pointer
    // reference instruction, e.g.: arm64-adrp reg, gotptr(address the
    // pointer-to-pointer got pointer), arm64-ldr reg, [reg](load the real
    // global variable pointer), for more implementation details, see
    // object-llvm.cpp::convert_reloc_type for more information
    return belong(reinterpret_cast<uint64_t>(cur->target)) ? &cur->target
                                                           : cur->target;
  }
  return cur->target;
}

Object::~Object() {}

MachOObject::MachOObject(std::string_view srcpath, std::string_view path)
    : Object(srcpath, path) {}

MachOObject::~MachOObject() {}

MachORelocObject::MachORelocObject(std::string_view srcpath,
                                   std::string_view path)
    : MachOObject(srcpath, path) {
  createFromFile(MachO_Reloc);
}

MachORelocObject::~MachORelocObject() {}

MachOMemoryObject::MachOMemoryObject(
    std::string_view name, std::unique_ptr<::llvm::MemoryBuffer> memobj)
    : MachOObject(name, name) {
  fbuf_ = std::move(memobj);
  createFromMemory(MachO_Reloc);
}

MachOMemoryObject::~MachOMemoryObject() {}

MachOExeObject::MachOExeObject(std::string_view srcpath, std::string_view path)
    : MachOObject(srcpath, path) {
  createFromFile(MachO_Exe);
}

MachOExeObject::~MachOExeObject() {}

ELFObject::ELFObject(std::string_view srcpath, std::string_view path)
    : Object(srcpath, path) {}

ELFObject::~ELFObject() {}

ELFRelocObject::ELFRelocObject(std::string_view srcpath, std::string_view path)
    : ELFObject(srcpath, path) {
  createFromFile(ELF_Reloc);
}

ELFRelocObject::~ELFRelocObject() {}

ELFMemoryObject::ELFMemoryObject(std::string_view name,
                                 std::unique_ptr<::llvm::MemoryBuffer> memobj)
    : ELFObject(name, name) {
  fbuf_ = std::move(memobj);
  createFromMemory(ELF_Reloc);
}

ELFMemoryObject::~ELFMemoryObject() {}

ELFExeObject::ELFExeObject(std::string_view srcpath, std::string_view path)
    : ELFObject(srcpath, path) {
  createFromFile(ELF_Exe);
}

ELFExeObject::~ELFExeObject() {}

COFFObject::COFFObject(std::string_view srcpath, std::string_view path)
    : Object(srcpath, path) {}

COFFObject::~COFFObject() {}

COFFRelocObject::COFFRelocObject(std::string_view srcpath,
                                 std::string_view path)
    : COFFObject(srcpath, path) {
  createFromFile(COFF_Reloc);
}

COFFRelocObject::~COFFRelocObject() {}

COFFMemoryObject::COFFMemoryObject(std::string_view name,
                                   std::unique_ptr<::llvm::MemoryBuffer> memobj)
    : COFFObject(name, name) {
  fbuf_ = std::move(memobj);
  createFromMemory(COFF_Reloc);
}

COFFMemoryObject::~COFFMemoryObject() {}

COFFExeObject::COFFExeObject(std::string_view srcpath, std::string_view path)
    : COFFObject(srcpath, path) {
  createFromFile(COFF_Exe);
}

COFFExeObject::~COFFExeObject() {}

InterpObject::InterpObject(std::string_view srcpath, std::string_view path)
    : Object(srcpath, path) {
  namespace iobj = com::vpand::icppiobj;
  namespace base64 = boost::beast::detail::base64;

  // herein we pass IsVolatile as true to disable llvm to mmap this file
  // because some data sections may be modified at runtime
  auto errBuff = llvm::MemoryBuffer::getFile(path_, false, true, true);
  if (!errBuff) {
    std::cout << "Failed to read '" << path_
              << "': " << errBuff.getError().message() << std::endl;
    return;
  }
  // construct the iobject instance
  iobj::InterpObject iobject;
  if (!iobject.ParseFromArray(errBuff.get()->getBufferStart(),
                              errBuff.get()->getBufferSize())) {
    log_print(Runtime, "Can't load the file {}, it's corrupted.", path_);
    return;
  }
  if (iobject.magic() != iobj_magic) {
    log_print(
        Runtime,
        "Can't load the file {}, it isn't an icpp interpretable object file.",
        path_);
    return;
  }
  if (iobject.version() != version_value().value) {
    log_print(Develop,
              "The file {} does be an icpp interpretable object, but its "
              "version doesn't match this icpp (expected {}).",
              path_, version_string());
    return;
  }

  // get the original object buffer
  ofbuf_ = iobject.objbuf();
  auto obuffer = llvm::MemoryBuffer::getMemBuffer(
      llvm::StringRef(ofbuf_.data(), ofbuf_.size()), path, false);

  auto buffRef = llvm::MemoryBufferRef(*obuffer);
  auto expObj = CObjectFile::createObjectFile(buffRef);
  if (!expObj) {
    std::cout << "Failed to create llvm object: "
              << llvm::toString(std::move(expObj.takeError())) << std::endl;
    return;
  }
  ofile_ = std::move(expObj.get());
  arch_ = static_cast<ArchType>(iobject.arch());
  type_ = static_cast<ObjectType>(iobject.otype());
  odiser_.init(ofile_.get(), triple());

  // parse from original object
  parseSections();
  parseSymbols();

  auto iins = iobject.instinfos();
  for (size_t i = 0; i < iins.size(); i++) {
    auto &iinfs = textsects_[i].iinfs;
    iinfs.resize(iins[i].infos_size());
    // copy all the decoed instruction information
    std::memcpy(&iinfs[0], iins[i].infos().data(),
                sizeof(InsnInfo) * iinfs.size());
  }

  auto imetas = iobject.instmetas();
  for (auto &m : imetas) {
    // decode base64 key
    std::string tmpkey(base64::decoded_size(m.first.length()), '\0');
    auto decret =
        base64::decode(tmpkey.data(), m.first.data(), m.first.length());
    // load instruction meta datas
    idecinfs_.insert({std::string(tmpkey.data(), decret.first), m.second});
  }

  auto imods = iobject.modules();
  auto irefs = iobject.irefsyms();
  for (auto &r : irefs) {
    // dependent module
    auto module = imods[r.module()];
    if (module == "self") {
      uint64_t basevm =
          r.dindex() == -1
              ? textsects_[0].vm
              : reinterpret_cast<uint64_t>(dynsects_[r.dindex()].buffer.data());
      irelocs_.push_back(RelocInfo{
          r.symbol(), reinterpret_cast<void *>(r.rva() + basevm), r.type()});
      continue;
    }
    Loader loader(module);
    if (!loader.valid()) {
      // reset to invalid architecture
      arch_ = Unsupported;
      return;
    }
    auto data = r.type() == CSymbolRef::ST_Data;
    if (loader.valid()) {
      // resolve this symbol in the current module
      auto target = loader.locate(r.symbol(), data);
      // if fail then abort, never return
      if (!target)
        target = Loader::locateSymbol(r.symbol(), data);
      irelocs_.push_back(RelocInfo{r.symbol(), target, r.type()});
    } else {
      // the final chance to resolve this symbol, abort if fails
      irelocs_.push_back(RelocInfo{
          r.symbol(), Loader::locateSymbol(r.symbol(), data), r.type()});
    }
  }
}

InterpObject::~InterpObject() {}

bool InterpObject::belong(uint64_t vm, size_t *di) {
  auto vmstr = reinterpret_cast<char *>(vm);
  if (ofbuf_.data() <= vmstr && vmstr < ofbuf_.data() + ofbuf_.length())
    return true;
  // in dynamically allocated section, .e.g.: bss
  for (auto &s : dynsects_) {
    if (s.buffer.data() <= vmstr && vmstr < s.buffer.data() + s.buffer.size()) {
      if (di) {
        di[0] = &s - &dynsects_[0];
      }
      return true;
    }
  }
  return false;
}

SymbolHash::SymbolHash(std::string_view path) : Object("", path) {}

SymbolHash::~SymbolHash() {}

std::vector<uint32_t> SymbolHash::hashes(std::string &message) {
  std::vector<uint32_t> result;
  auto errBuff = llvm::MemoryBuffer::getFile(path_);
  if (!errBuff) {
    message = std::format("Failed to read '{}': ", path_,
                          errBuff.getError().message());
    return result;
  }
  auto buffRef = llvm::MemoryBufferRef(*errBuff.get());
  auto expObj = CObjectFile::createObjectFile(buffRef);
  if (expObj) {
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
    if (host_arch() != arch_) {
      message = std::format("Architecture mismatch, '{}' is expected.",
                            arch_name(host_arch()));
      return result;
    }
    parseSymbols();

    std::set<uint32_t> sorted;
    for (auto &sym : funcs_) {
      sorted.insert(std::hash<std::string>{}(sym.first));
    }
    for (auto &sym : funcs_) {
      sorted.insert(std::hash<std::string>{}(sym.first));
    }
    result.resize(sorted.size());
    std::copy(sorted.begin(), sorted.end(), result.begin());
  } else {
    message = std::format("Failed to create llvm object: {}.",
                          llvm::toString(std::move(expObj.takeError())));
  }
  return result;
}

std::shared_ptr<Object> create_object(std::string_view srcpath,
                                      std::string_view path, bool &validcache) {
  validcache = true;
  if (path.ends_with(iobj_ext)) {
    // it's the cache of the source file
    auto tmp = std::make_shared<InterpObject>(srcpath, path);
    return (validcache = tmp->valid()) ? tmp : nullptr;
  }
  if (!srcpath.length() && path.ends_with(obj_ext)) {
    // it's the cache of the module object file
    auto cache = convert_file(path, iobj_ext);
    if (cache.has_filename()) {
      auto tmp = std::make_shared<InterpObject>(srcpath, path);
      if ((validcache = tmp->valid())) {
        log_print(Develop, "Using iobject cache file when loading: {}.",
                  cache.string());
        return tmp;
      }
    }
    // continue to load the original object file with llvm
  }

  llvm::file_magic magic;
  auto err = llvm::identify_magic(llvm::Twine(path), magic);
  if (err) {
    log_print(Runtime, "Failed to identify the file type of '{}': {}.", path,
              err.message());
    return nullptr;
  }

  using fm = llvm::file_magic;
  switch (magic) {
  case fm::macho_object:
    return std::make_shared<MachORelocObject>(srcpath, path);
  case fm::macho_executable:
    return std::make_shared<MachOExeObject>(srcpath, path);
  case fm::elf_relocatable:
    return std::make_shared<ELFRelocObject>(srcpath, path);
  case fm::elf_executable:
    return std::make_shared<ELFExeObject>(srcpath, path);
  case fm::coff_object:
    return std::make_shared<COFFRelocObject>(srcpath, path);
  case fm::pecoff_executable:
    return std::make_shared<COFFExeObject>(srcpath, path);
  default:
    log_print(Runtime,
              "Unsupported input file type {} "
              ", currently supported file type includes "
              "MachO/ELF/PE-Object/Executable.",
              static_cast<uint32_t>(magic));
    return nullptr;
  }
}

} // namespace icpp
