/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#include "platform.h"

#if __APPLE__
// there's an extra underscore character in macho symbol, skip it
#define symbol_name(raw) (raw.data() + 1)
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
#error Un-implement symbol lookup on Windows.
#else
  return dlsym(RTLD_DEFAULT, symbol_name(raw));
#endif
}

const void *find_symbol(const void *handle, std::string_view raw) {
  if (!handle)
    return find_symbol(raw);

#if ON_WINDOWS
  return ::GetProcAddress(reinterpret_cast<HMODULE>(const_cast<void *>(handle)),
                          symbol_name(raw));
#else
  return dlsym(const_cast<void *>(handle), symbol_name(raw));
#endif
}

#if __linux__
static int iter_so_callback(dl_phdr_info *info, size_t size, void *data) {
  auto callback = *reinterpret_cast<
      std::function<void(uint64_t base, std::string_view path)> *>(data);
  callback(reinterpret_cast<uint64_t>(info->dlpi_addr), info->dlpi_name);
  return 0;
}
#endif

void iterate_modules(
    const std::function<void(uint64_t base, std::string_view path)> &callback) {
#if __APPLE__
  for (uint32_t i = 0; i < _dyld_image_count(); i++) {
    callback(reinterpret_cast<uint64_t>(_dyld_get_image_header(i)),
             _dyld_get_image_name(i));
  }
#elif __linux__
  dl_iterate_phdr(iter_so_callback, &callback);
#elif _WIN32
  HANDLE hProcess = ::GetCurrentProcess();
  HMODULE hMods[4096];
  DWORD cbNeeded;
  ::EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
  for (unsigned i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
    char szModName[MAX_PATH];
    ::GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName));
    callback(reinterpret_cast<uint64_t>(::GetModuleHandle(szModName)),
             szModName);
  }
#else
#error Unsupported host os platform.
#endif
}

std::vector<std::string> extra_cflags() {
  std::vector<std::string> args;
#if __APPLE__
#define MACOSX_SDK                                                             \
  "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/"      \
  "Developer/SDKs/MacOSX.sdk"
  args.push_back("-isysroot");
  args.push_back(MACOSX_SDK);
#elif __linux__
#error Un-implement the Linux platform currently.
#elif ON_WINDOWS
#error Un-implement the Windows platform currently.
#else
#error Unknown compiling platform.
#endif
  return args;
}

} // namespace icpp
