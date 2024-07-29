/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "platform.h"
#include "arch.h"
#include "runcfg.h"
#include "utils.h"
#include <set>

#if __APPLE__
// there's an extra underscore character in macho symbol, skip it
#define symbol_name(raw) (raw.data() + 1)

#ifdef mmap
// special implementations for unicorn engine on iphone os
#undef mmap
#undef munmap
extern "C" {

void *mmap(void *start, size_t length, int prot, int flags, int fd,
           off_t offset);
void *icpp_gadget_mmap(void *start, size_t length, int prot, int flags, int fd,
                       off_t offset) {
  if (length < mem_page_size)
    return mmap(start, length, prot, flags, fd, offset);

  void *result;
  vm_allocate(mach_task_self(), (vm_address_t *)&result, length,
              VM_FLAGS_ANYWHERE);
  mprotect(result, length, prot);
  return result;
}

int munmap(void *addr, size_t sz);
int icpp_gadget_munmap(void *addr, size_t sz) {
  if (sz < mem_page_size)
    return munmap(addr, sz);

  vm_deallocate(mach_thread_self(), (vm_address_t)addr, sz);
  return 0;
}

void pthread_jit_write_protect_np(int enable) {
  static bool tried = false;
  static void (*fnptr)(int) = nullptr;
  if (tried) {
    if (fnptr)
      fnptr(enable);
    return;
  }
  tried = true;
  fnptr = (void (*)(int))icpp::find_symbol(nullptr,
                                           "_pthread_jit_write_protect_np");
  if (fnptr)
    fnptr(enable);
}
}
#else
#ifndef __MAC_11_3
// qemu's tcg engine references this api, but:
// pthread_jit_write_protect_np is only available on macOS 11.0 or newer, and:
// qemu's configure script can't detect this situation properly, so:
// we implement it as a nop function to make it working.
extern "C" void pthread_jit_write_protect_np(int enable) {}
#endif
#endif
#elif ON_WINDOWS
static constexpr const char *symbol_name(std::string_view raw) {
  return raw.data() + (raw.starts_with("__imp_") ? 6 : 0);
}
#else
#define symbol_name(raw) (raw.data() + 0)
#endif

namespace icpp {

const void *load_library(std::string_view path) {
#if ON_WINDOWS
  auto handle = reinterpret_cast<void *>(::LoadLibraryExA(
      path.data(), nullptr,
      LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS |
          LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR));
  if (handle)
    return handle;

  char buff[512];
  ::FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   nullptr, ::GetLastError(), 0, buff, sizeof(buff), nullptr);
  log_print(Runtime, "Failed to load {}: {}", path.data(), buff);
#else
  auto handle = dlopen(path.data(), RTLD_NOW);
  if (handle)
    return handle;

  log_print(Runtime, "{}", dlerror());
#endif
  return nullptr;
}

static const void *find_symbol(std::string_view raw) {
#ifdef ON_WINDOWS
  static std::set<HMODULE> sysmods;
  // find in the cached module
  for (auto &mod : sysmods) {
    auto addr =
        reinterpret_cast<const void *>(::GetProcAddress(mod, symbol_name(raw)));
    if (addr)
      return addr;
  }
  // find in the whole program
  const void *addr = nullptr;
  iterate_modules([&addr, &raw](uint64_t handle, std::string_view path) {
    addr = reinterpret_cast<const void *>(
        ::GetProcAddress(reinterpret_cast<HMODULE>(handle), symbol_name(raw)));
    if (addr)
      sysmods.insert(reinterpret_cast<HMODULE>(handle));
    return addr != nullptr;
  });
  return addr;
#else
  return dlsym(RTLD_DEFAULT, symbol_name(raw));
#endif
}

const void *find_symbol(const void *handle, std::string_view raw) {
  if (!handle)
    return find_symbol(raw);

#if ON_WINDOWS
  return reinterpret_cast<const void *>(::GetProcAddress(
      reinterpret_cast<HMODULE>(const_cast<void *>(handle)), symbol_name(raw)));
#else
  return dlsym(const_cast<void *>(handle), symbol_name(raw));
#endif
}

#if __linux__
static int iter_so_callback(dl_phdr_info *info, size_t size, void *data) {
  auto callback = *reinterpret_cast<
      std::function<bool(uint64_t base, std::string_view path)> *>(data);
  return callback(static_cast<uint64_t>(info->dlpi_addr), info->dlpi_name);
}
#endif

void iterate_modules(
    const std::function<bool(uint64_t base, std::string_view path)> &callback) {
#if __APPLE__
  for (uint32_t i = 0; i < _dyld_image_count(); i++) {
    if (callback(reinterpret_cast<uint64_t>(_dyld_get_image_header(i)),
                 _dyld_get_image_name(i)))
      return;
  }
#elif __linux__
  dl_iterate_phdr(
      iter_so_callback,
      reinterpret_cast<void *>(
          const_cast<std::function<bool(uint64_t base, std::string_view path)>
                         *>(&callback)));
#elif ON_WINDOWS
  HANDLE hProcess = ::GetCurrentProcess();
  HMODULE hMods[4096];
  DWORD cbNeeded;
  ::EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
  for (unsigned i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
    char szModName[MAX_PATH];
    ::GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName));
    if (callback(reinterpret_cast<uint64_t>(hMods[i]), szModName))
      return;
  }
#else
#error Unsupported host os platform.
#endif
}

} // namespace icpp
