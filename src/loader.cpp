/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "loader.h"
#include "exec.h"
#include "log.h"
#include "object.h"
#include "platform.h"
#include <cstdio>
#include <iostream>
#include <locale>
#include <map>
#include <mutex>
#include <stdio.h>
#include <thread>
#include <unordered_map>

namespace icpp {

// some simulated system global variables
static uint64_t __dso_handle = 0;

struct ModuleLoader {
  ModuleLoader() : mainid_(std::this_thread::get_id()) {
    syms_.insert({"___dso_handle", &__dso_handle});
  }

  bool isMain() { return mainid_ == std::this_thread::get_id(); }

  struct LockGuard {
    LockGuard(ModuleLoader *p, std::recursive_mutex &m)
        : parent_(p), mutex_(m) {
      if (!parent_->isMain())
        mutex_.lock();
    }

    ~LockGuard() {
      if (!parent_->isMain())
        mutex_.unlock();
    }

    ModuleLoader *parent_;
    std::recursive_mutex &mutex_;
  };

  const void *loadLibrary(std::string_view path);
  const void *resolve(const void *handle, std::string_view name, bool data);
  const void *resolve(std::string_view name, bool data);
  std::string find(const void *addr, bool update);

  // it'll be invoked by execute engine when loaded a iobject module
  void cacheObject(std::shared_ptr<Object> imod);

  bool executable(uint64_t vm, Object **iobject) {
    for (auto m : imods_) {
      if (m->executable(vm, nullptr)) {
        iobject[0] = m.get();
        return true;
      }
    }
    return false;
  }

  bool belong(uint64_t vm) {
    for (auto m : imods_) {
      if (m->belong(vm))
        return true;
    }
    return false;
  }

private:
  const void *lookup(std::string_view name, bool data);
#if __linux__
  friend int iter_so_callback(dl_phdr_info *info, size_t size, void *data);
#endif

  std::thread::id mainid_;
  std::recursive_mutex mutex_;

  // cached symbols
  std::unordered_map<std::string, const void *> syms_;

  // native modules
  std::map<uint64_t, std::string> mods_;
  std::vector<std::map<uint64_t, std::string>::iterator> modits_;
  std::map<std::string, const void *> mhandles_;

  // iobject modules
  std::vector<std::shared_ptr<Object>> imods_;
} symcache;

const void *ModuleLoader::loadLibrary(std::string_view path) {
  LockGuard lock(this, mutex_);
  auto found = mhandles_.find(path.data());
  if (found == mhandles_.end()) {
    auto addr = load_library(path.data());
    if (!addr) {
      if (path.ends_with(iobj_ext)) {
        // check the already loaded/cached iobject module
        auto found = mhandles_.find(path.data());
        if (found != mhandles_.end()) {
          return found->second;
        }

        auto object = std::make_shared<InterpObject>("", path);
        if (object->valid()) {
          // initialize this iobject module, call its construction functions
          init_library(object);

          // save to iobject module list
          imods_.push_back(object);
          addr = object.get();
        }
      }
      if (!addr) {
        log_print(Runtime, "Failed to load library: {}", path.data());
        exit(-1);
      }
    }
    if (addr)
      log_print(Runtime, "Loaded module {}.", path.data());
    found = mhandles_.insert({path.data(), addr}).first;
  }
  return found->second;
}

const void *ModuleLoader::resolve(const void *handle, std::string_view name,
                                  bool data) {
  LockGuard lock(this, mutex_);
  auto found = syms_.find(name.data());
  if (found != syms_.end()) {
    return data ? &found->second : found->second;
  }

  const void *target = nullptr;

  // check it in iobject modules
  for (auto io : imods_) {
    if (handle != io.get())
      continue;
    auto t = io->locateSymbol(name);
    if (t) {
      target = t;
      break;
    }
  }

  // check it in native modules
  if (!target) {
    target = find_symbol(const_cast<void *>(handle), name);
  }

  if (!target)
    return nullptr;
  found = syms_.insert({name.data(), target}).first;
  return data ? &found->second : found->second;
}

const void *ModuleLoader::resolve(std::string_view name, bool data) {
  LockGuard lock(this, mutex_);
  auto found = syms_.find(name.data());
  if (found != syms_.end()) {
    return data ? &found->second : found->second;
  }
  return lookup(name, data);
}

const void *ModuleLoader::lookup(std::string_view name, bool data) {
  const void *target = nullptr;

  // check it in iobject modules
  for (auto io : imods_) {
    auto t = io->locateSymbol(name);
    if (t) {
      target = t;
      break;
    }
  }

  // check it in native system modules
  if (!target)
    target = find_symbol(nullptr, name);

  if (!target) {
    log_print(Runtime, "Fatal error, failed to resolve symbol: {}.", dlerror());
    std::exit(-1);
  }

  // cache it
  auto newit = syms_.insert({name.data(), target}).first;
  return data ? &newit->second : newit->second;
}

std::string ModuleLoader::find(const void *addr, bool update) {
  if (mods_.size() == 0 || update) {
    LockGuard lock(this, mutex_);
    iterate_modules([](uint64_t base, std::string_view path) {
      symcache.mods_.insert({base, path.data()});
    });
    // reset module iterators
    modits_.clear();
    for (auto it = mods_.begin(); it != mods_.end(); it++) {
      modits_.push_back(it);
    }
  }
  // check it in iobject module
  for (auto m : imods_) {
    if (m->belong(reinterpret_cast<uint64_t>(addr))) {
      return m->cachePath();
    }
  }
  // binary search for the module
  long low = 0;
  long high = modits_.size() - 1;
  auto target = reinterpret_cast<uint64_t>(addr);
  while (low <= high) {
    auto mid = (low + high) / 2;
    if (mid + 1 == modits_.size()) {
      return modits_[mid]->second.data();
    }
    auto base0 = modits_[mid]->first;
    auto base1 = modits_[mid + 1]->first;
    if (base0 <= target && target < base1) {
      // if target is between base0 and base1, we think it belongs to base0
      return modits_[mid]->second.data();
    }
    if (base0 > target) {
      // back forward
      high = mid - 1;
    } else {
      // go forward
      low = mid + 1;
    }
  }
  return "";
}

void ModuleLoader::cacheObject(std::shared_ptr<Object> imod) {
  if (mhandles_.find(imod->path().data()) != mhandles_.end())
    return;
  imods_.push_back(imod);
  mhandles_.insert({imod->path().data(), reinterpret_cast<void *>(imod.get())});
}

Loader::Loader(Object *object, const std::vector<std::string> &deps)
    : object_(object) {
  for (auto &m : deps) {
    symcache.loadLibrary(m);
  }
}

Loader::Loader(std::string_view module)
    : handle_(symcache.loadLibrary(module)) {}

Loader::~Loader() {}

bool Loader::valid() { return object_ || handle_; }

const void *Loader::locate(std::string_view name, bool data) {
  return symcache.resolve(handle_, name, data);
}

const void *Loader::locateSymbol(std::string_view name, bool data) {
  return symcache.resolve(name, data);
}

std::string Loader::locateModule(const void *addr, bool update) {
  return symcache.find(addr, update);
}

void Loader::cacheObject(std::shared_ptr<Object> imod) {
  symcache.cacheObject(imod);
}

bool Loader::executable(uint64_t vm, Object **iobject) {
  return symcache.executable(vm, iobject);
}

bool Loader::belong(uint64_t vm) { return symcache.belong(vm); }

} // namespace icpp
