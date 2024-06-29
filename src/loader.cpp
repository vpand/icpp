/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "loader.h"
#include "log.h"
#include "object.h"
#include <cstdio>
#include <iostream>
#include <locale>
#include <map>
#include <mutex>
#include <stdio.h>
#include <thread>
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#if __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

extern void *__stack_chk_guard;

namespace icpp {

// these global variables will have function type in object file
// we must fix them as data type to make its related instructions to execute
// correctly
static const void *global_vars[] = {
    reinterpret_cast<const void *>(&std::cout),
    reinterpret_cast<const void *>(&std::wcout),
    reinterpret_cast<const void *>(&std::ctype<char>::id),
    reinterpret_cast<const void *>(&std::ctype<wchar_t>::id),
    reinterpret_cast<const void *>(&stdin),
    reinterpret_cast<const void *>(&stdout),
    reinterpret_cast<const void *>(&stderr),
    reinterpret_cast<const void *>(&__stack_chk_guard),
};

static bool is_global_var(const void *p) {
  for (size_t i = 0; i < std::size(global_vars); i++) {
    if (p == global_vars[i]) {
      return true;
    }
  }
  return false;
}

struct SymbolCache {
  SymbolCache() : mainid_(std::this_thread::get_id()) {}

  bool isMain() { return mainid_ == std::this_thread::get_id(); }

  struct LockGuard {
    LockGuard(SymbolCache *p, std::recursive_mutex &m) : parent_(p), mutex_(m) {
      if (!parent_->isMain())
        mutex_.lock();
    }

    ~LockGuard() {
      if (!parent_->isMain())
        mutex_.unlock();
    }

    SymbolCache *parent_;
    std::recursive_mutex &mutex_;
  };

  const void *loadLibrary(std::string_view path);
  const void *resolve(const void *handle, std::string_view name, bool data);
  const void *resolve(std::string_view name, bool data);
  std::string find(const void *addr, bool update);

  // it'll be invoked by execute engine when loaded a iobject module
  void cacheObject(std::shared_ptr<Object> imod) { imods_.push_back(imod); }

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
  std::map<std::string, void *> mhandles_;
  // iobject modules
  std::vector<std::shared_ptr<Object>> imods_;
} symcache;

const void *SymbolCache::loadLibrary(std::string_view path) {
  LockGuard lock(this, mutex_);
  auto found = mhandles_.find(path.data());
  if (found == mhandles_.end()) {
#if _WIN32
    auto addr = ::LoadLibraryA(path.data());
#else
    auto addr = dlopen(path.data(), RTLD_NOW);
#endif
    if (!addr) {
      if (path.ends_with(".io")) {
        auto object = std::make_shared<InterpObject>("", path);
        if (object->valid()) {
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
    found =
        mhandles_.insert({path.data(), reinterpret_cast<void *>(addr)}).first;
  }
  return found->second;
}

const void *SymbolCache::resolve(const void *handle, std::string_view name,
                                 bool data) {
  LockGuard lock(this, mutex_);
  auto found = syms_.find(name.data());
  if (found != syms_.end()) {
    if (data || is_global_var(found->second))
      return &found->second;
    return found->second;
  }

  const void *target = nullptr;

  // check it in iobject modules
  for (auto io : imods_) {
    if (handle != io.get())
      continue;
    auto t = io->locateSymbol(name, data);
    if (t) {
      target = t;
      break;
    }
  }

  // check it in native modules
  if (!target) {
#if _WIN32
    auto addr = ::GetProcAddress(
        reinterpret_cast<HMODULE>(const_cast<void *>(handle)), name.data());
#else
#if __APPLE__
    auto sym = name.data() + 1;
#else
    auto sym = name.data();
#endif
    target = dlsym(const_cast<void *>(handle), sym);
#endif
  }

  if (!target)
    return nullptr;
  found = syms_.insert({name.data(), target}).first;
  return (data || is_global_var(found->second)) ? &found->second
                                                : found->second;
}

const void *SymbolCache::resolve(std::string_view name, bool data) {
  LockGuard lock(this, mutex_);
  auto found = syms_.find(name.data());
  if (found != syms_.end()) {
    if (data || is_global_var(found->second))
      return &found->second;
    return found->second;
  }
  return lookup(name, data);
}

const void *SymbolCache::lookup(std::string_view name, bool data) {
  const void *target = nullptr;

  // check it in iobject modules
  for (auto io : imods_) {
    auto t = io->locateSymbol(name, data);
    if (t) {
      target = t;
      break;
    }
  }

  // check it in native system modules
  if (!target) {
#ifdef _WIN32
#error Un-implement symbol lookup on Windows.
#else
#if __APPLE__
    auto sym = name.data() + 1;
#else
    auto sym = name.data();
#endif
    target = dlsym(RTLD_DEFAULT, sym);
#endif
  }
  if (!target) {
    log_print(Runtime, "Fatal error, failed to resolve symbol: {}.", dlerror());
    std::exit(-1);
  }

  // cache it
  auto newit = syms_.insert({name.data(), target}).first;
  if (data || is_global_var(newit->second))
    return &newit->second;
  return newit->second;
}

#if __linux__
int iter_so_callback(dl_phdr_info *info, size_t size, void *data) {
  symcache.mods_.insert(
      {reinterpret_cast<uint64_t>(info->dlpi_addr), info->dlpi_name});
  return 0;
}
#endif

std::string SymbolCache::find(const void *addr, bool update) {
  if (mods_.size() == 0 || update) {
    LockGuard lock(this, mutex_);
#if __APPLE__
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
      symcache.mods_.insert(
          {reinterpret_cast<uint64_t>(_dyld_get_image_header(i)),
           _dyld_get_image_name(i)});
    }
#elif __linux__
    dl_iterate_phdr(iter_so_callback, nullptr);
#elif _WIN32
    HANDLE hProcess = ::GetCurrentProcess();
    HMODULE hMods[4096];
    DWORD cbNeeded;
    ::EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
    for (unsigned i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
      char szModName[MAX_PATH];
      ::GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName));
      symcache.mods_.insert(
          {reinterpret_cast<uint64_t>(::GetModuleHandle(szModName)),
           szModName});
    }
#else
#error Unsupported host os platform.
#endif
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
