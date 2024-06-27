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
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#if __APPLE__
#include <mach-o/dyld.h>
#endif
#endif

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
  const void *resolve(std::string_view name, bool data);
  std::string_view find(const void *addr, bool update);

private:
  const void *lookup(std::string_view name, bool data);
#if __linux__
  friend int iter_so_callback(dl_phdr_info *info, size_t size, void *data);
#endif

  std::mutex mutext_;
  std::unordered_map<std::string, const void *> syms_;
  std::map<uint64_t, std::string> mods_;
  std::vector<std::map<uint64_t, std::string>::iterator> modits_;
} symcache;

const void *SymbolCache::resolve(std::string_view name, bool data) {
  std::lock_guard lock(mutext_);
  auto found = syms_.find(name.data());
  if (found != syms_.end()) {
    if (data || is_global_var(found->second))
      return &found->second;
    return found->second;
  }
  return lookup(name, data);
}

const void *SymbolCache::lookup(std::string_view name, bool data) {
#ifdef _WIN32
#error Un-implement symbol lookup on Windows.
#else
#if __APPLE__
  auto sym = name.data() + 1;
#else
  auto sym = name.data();
#endif
  auto addr = dlsym(RTLD_DEFAULT, sym);
  if (!addr) {
    log_print(Runtime, "Fatal error, failed to resolve symbol: {}.", dlerror());
    abort();
  }
#endif
  // cache it
  auto newit = syms_.insert({sym, addr}).first;
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

std::string_view SymbolCache::find(const void *addr, bool update) {
  if (mods_.size() == 0 || update) {
    std::lock_guard lock(mutext_);
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
    : object_(object) {}

Loader::~Loader() {}

bool Loader::valid() { return true; }

const void *Loader::locateSymbol(std::string_view name, bool data) {
  return symcache.resolve(name, data);
}

std::string_view Loader::locateModule(const void *addr, bool update) {
  return symcache.find(addr, update);
}

} // namespace icpp
