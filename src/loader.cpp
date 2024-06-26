/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "loader.h"
#include "log.h"
#include "object.h"
#include <mutex>
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

namespace icpp {

struct SymbolCache {
  const void *resolve(std::string_view name, bool data);

private:
  const void *lookup(std::string_view name, bool data);

  std::mutex mutext_;
  std::unordered_map<std::string, const void *> syms_;
} symcache;

const void *SymbolCache::resolve(std::string_view name, bool data) {
  std::lock_guard lock(mutext_);
  auto found = syms_.find(name.data());
  if (found != syms_.end()) {
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
  syms_.insert({sym, addr});
  return addr;
}

Loader::Loader(Object *object, const std::vector<std::string> &deps)
    : object_(object) {}

Loader::~Loader() {}

bool Loader::valid() { return true; }

const void *Loader::locateSymbol(std::string_view name, bool data) {
  return symcache.resolve(name, data);
}

} // namespace icpp
