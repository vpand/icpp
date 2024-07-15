/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "platform.h"
#include "arch.h"
#include "runcfg.h"
#include "utils.h"
#include <vector>

#if __APPLE__
// there's an extra underscore character in macho symbol, skip it
#define symbol_name(raw) (raw.data() + 1)

#ifndef __MAC_11_2
// qemu's tcg engine references this api, but:
// pthread_jit_write_protect_np is only available on macOS 11.0 or newer, and:
// qemu's configure script can't detect this situation properly, so:
// we implement it as a nop function to make it working.
extern "C" void pthread_jit_write_protect_np(int enable) {}
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
  return reinterpret_cast<void *>(::LoadLibraryA(path.data()));
#else
  return dlopen(path.data(), RTLD_NOW);
#endif
}

static const void *find_symbol(std::string_view raw) {
#ifdef ON_WINDOWS
  static std::vector<HMODULE> sysmods;
  if (!sysmods.size()) {
    static std::vector<std::string_view> names{
        "api-ms-win", "vcruntime", "vcp", "kernel", "crt",
        "API-MS-WIN", "VCRUNTIME", "VCP", "KERNEL", "CRT"};
    iterate_modules([](uint64_t handle, std::string_view path) {
      for (auto &n : names) {
        if (path.find(n) != std::string_view::npos) {
          sysmods.push_back(reinterpret_cast<HMODULE>(handle));
          break;
        }
      }
      return false;
    });
    if (sysmods.size() < names.size() / 2) {
      log_print(Develop,
                "Warning, the count of the default system module handle should "
                "be at least the same size with the names's.");
    }
  }
  // search in the system modules
  for (auto &mod : sysmods) {
    auto addr =
        reinterpret_cast<const void *>(::GetProcAddress(mod, raw.data()));
    if (addr)
      return addr;
  }
  const void *addr = nullptr;
  iterate_modules([&addr, &raw](uint64_t handle, std::string_view path) {
    if (addr || path.find("Windows") != std::string_view::npos)
      return false;
    // search in the user modules
    addr = reinterpret_cast<const void *>(
        ::GetProcAddress(reinterpret_cast<HMODULE>(handle), raw.data()));
    return false;
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
  return callback(reinterpret_cast<uint64_t>(info->dlpi_addr), info->dlpi_name);
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
