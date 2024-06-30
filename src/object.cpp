/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "object.h"
#include "icpp.h"
#include "loader.h"
#include "utils.h"
#include <boost/beast.hpp>
#include <fstream>
#include <icppiobj.pb.h>
#include <iostream>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/MemoryBuffer.h>
#include <span>

namespace icpp {

Object::Object(std::string_view srcpath, std::string_view path)
    : srcpath_(srcpath), path_(path) {}

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
    odiser_.init(ofile_.get(), triple());
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

void Object::parseSections() {
  for (auto &s : ofile_->sections()) {
    auto expName = s.getName();
    if (!expName) {
      continue;
    }

    auto name = expName.get();
    if (s.isText()) {
      auto expContent = s.getContents();
      if (!expContent) {
        log_print(Runtime,
                  "Empty object file, there's no content of {} section.",
                  name.data());
        break;
      }
      auto news = textsects_.emplace_back(
          TextSection{static_cast<uint32_t>(s.getIndex()),
                      static_cast<uint32_t>(s.getSize()),
                      static_cast<uint32_t>(s.getAddress()),
                      reinterpret_cast<uint64_t>(expContent->data())});
      log_print(Develop, "Section {} rva={:x}, vm={:x} size={}.", name.data(),
                news.rva, news.vm, news.size);
    } else if (s.isBSS() || name.ends_with("bss") || name.ends_with("common")) {
      dynsects_.push_back({name.data(), static_cast<uint32_t>(s.getAddress()),
                           std::string(s.getSize(), 0)});
    }
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

static std::vector<const void *>
cdtor_entries(CObjectFile *ofile, const std::span<std::string_view> &names,
              const std::unordered_map<std::string, const void *> &funcs) {
  std::vector<const void *> results;
  for (auto &s : ofile->sections()) {
    auto expName = s.getName();
    if (!expName)
      continue;
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
            log_print(Runtime,
                      "Warning, failed to locate constructor function {}.",
                      symName->data());
        }
      }
    }
  }
  return results;
}

std::vector<const void *> Object::ctorEntries() {
  std::string_view names[] = {"init_func"};
  std::span sns{names, std::size(names)};
  return cdtor_entries(ofile_.get(), sns, funcs_);
}

std::vector<const void *> Object::dtorEntries() {
  std::string_view names[] = {"term_func"};
  std::span sns{names, std::size(names)};
  return cdtor_entries(ofile_.get(), sns, funcs_);
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
    auto expContent = s.getContents();
    if (!expContent)
      continue;
    auto start = reinterpret_cast<uint64_t>(expContent->data());
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
  if (vm2rva(vm) != -1)
    return true;
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
    if (!belong(reinterpret_cast<uint64_t>(r.target))) {
      refmods.insert(Loader::locateModule(r.target).data());
    }
  }
  imods->Add("self");
  for (auto &m : refmods) {
    imods->Add(fs::absolute(m));
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
      ri.set_dindex(0);
      ri.set_rva(0);
      for (size_t i = 0; i < imods->size(); i++) {
        if (imods->at(i) == Loader::locateModule(r.target)) {
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
  if (cur->type == llvm::object::SymbolRef::ST_Data) {
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
  createObject(MachO_Reloc);
}

MachORelocObject::~MachORelocObject() {}

MachOExeObject::MachOExeObject(std::string_view srcpath, std::string_view path)
    : MachOObject(srcpath, path) {
  createObject(MachO_Exe);
}

MachOExeObject::~MachOExeObject() {}

ELFObject::ELFObject(std::string_view srcpath, std::string_view path)
    : Object(srcpath, path) {}

ELFObject::~ELFObject() {}

ELFRelocObject::ELFRelocObject(std::string_view srcpath, std::string_view path)
    : ELFObject(srcpath, path) {
  createObject(ELF_Reloc);
}

ELFRelocObject::~ELFRelocObject() {}

ELFExeObject::ELFExeObject(std::string_view srcpath, std::string_view path)
    : ELFObject(srcpath, path) {
  createObject(ELF_Exe);
}

ELFExeObject::~ELFExeObject() {}

COFFObject::COFFObject(std::string_view srcpath, std::string_view path)
    : Object(srcpath, path) {}

COFFObject::~COFFObject() {}

COFFRelocObject::COFFRelocObject(std::string_view srcpath,
                                 std::string_view path)
    : COFFObject(srcpath, path) {
  createObject(COFF_Reloc);
}

COFFRelocObject::~COFFRelocObject() {}

COFFExeObject::COFFExeObject(std::string_view srcpath, std::string_view path)
    : COFFObject(srcpath, path) {
  createObject(COFF_Exe);
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
        "Can't load the file {}, it isn't a icpp interpretable object file.",
        path_);
    return;
  }
  if (iobject.version() != version_value().value) {
    log_print(Runtime,
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
    if (loader.valid()) {
      auto target = loader.locate(r.symbol(),
                                  r.type() == llvm::object::SymbolRef::ST_Data);
      // if fail then abort, never return
      if (!target)
        target = Loader::locateSymbol(r.symbol(), false);
      irelocs_.push_back(RelocInfo{r.symbol(), target, r.type()});
    } else {
      log_print(Runtime, "Can't load dependent module {}.", module);
      std::exit(-1);
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

} // namespace icpp
