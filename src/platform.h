/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#if defined(_WIN32) || defined(_WIN64)
#define ON_WINDOWS 1
#else
#define ON_UNIX 1
#endif

#include <functional>
#include <string_view>

#if ON_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <Windows.h>
#include <psapi.h>

#undef min
#undef max

#if _M_X64
#define __x64__ 1
#endif

#define __ICPP_EXPORT__ __declspec(dllexport)
#else
#include <dlfcn.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#if __APPLE__
#include <AvailabilityVersions.h>
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <mach/vm_prot.h>
#else
#include <link.h>
#endif

#define __ICPP_EXPORT__ __attribute__((visibility("default")))
#endif // end of ON_WINDOWS

namespace icpp {

#ifdef ON_WINDOWS

typedef HANDLE (*thread_create_t)(LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                  SIZE_T dwStackSize,
                                  LPTHREAD_START_ROUTINE lpStartAddress,
                                  LPVOID lpParameter, DWORD dwCreationFlags,
                                  LPDWORD lpThreadId);

typedef DWORD thread_return_t;

const thread_create_t thread_create = CreateThread;
constexpr const std::string_view env_home = "userprofile";
constexpr const std::string_view path_split = ";";
constexpr const std::string_view ndk_build = "ndk-build.bat";

static inline uint32_t mem_page_size_impl() {
  SYSTEM_INFO info;
  ::GetSystemInfo(&info);
  return info.dwPageSize;
}

#define mem_page_size mem_page_size_impl()

static inline char *page_alloc() {
  auto page =
      ::VirtualAlloc(nullptr, mem_page_size, MEM_RESERVE, PAGE_READWRITE);
  return reinterpret_cast<char *>(page);
}

static inline void page_free(const void *page) {
  ::VirtualFree(const_cast<void *>(page), mem_page_size, MEM_RELEASE);
}

static inline void page_flush(const void *page) {
  ::FlushInstructionCache(::GetCurrentProcess(), page, mem_page_size);
}

static inline void page_protect(const void *page, DWORD perms) {
  DWORD old;
  ::VirtualProtect(const_cast<void *>(page), mem_page_size, perms, &old);
}

static inline void page_writable(const void *page) {
  page_protect(page, PAGE_READWRITE);
}

static inline void page_executable(const void *page) {
  page_protect(page, PAGE_EXECUTE_READ);
}

extern "C" {
void _CxxThrowException(void);

// rename to libc++abi's symbol name
#define __cxa_throw _CxxThrowException
#define __cxa_atexit atexit
#define __stack_chk_fail abort
}

#else

typedef int (*thread_create_t)(pthread_t *thread, const pthread_attr_t *attr,
                               void *(*start_routine)(void *), void *arg);
typedef void *thread_return_t;

const thread_create_t thread_create = pthread_create;
constexpr const std::string_view env_home = "HOME";
constexpr const std::string_view path_split = ":";
constexpr const std::string_view ndk_build = "ndk-build";

#if __APPLE__
#define mem_page_size ((int)PAGE_SIZE)

static inline char *page_alloc() {
  vm_address_t page;
  vm_allocate(mach_task_self(), &page, mem_page_size, VM_FLAGS_ANYWHERE);
  mprotect(reinterpret_cast<void *>(page), mem_page_size, PROT_WRITE);
  return reinterpret_cast<char *>(page);
}

static inline void page_free(const void *page) {
  vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(page),
                mem_page_size);
}

extern "C" void sys_icache_invalidate(const void *start, size_t len);

static inline void page_flush(const void *page) {
  sys_icache_invalidate(page, mem_page_size);
}
#else
#define mem_page_size getpagesize()

static inline char *page_alloc() {
  auto page = mmap(nullptr, mem_page_size, PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return reinterpret_cast<char *>(page);
}

static inline void page_free(const void *page) {
  munmap(const_cast<void *>(page), mem_page_size);
}

static inline void page_flush(const void *page) {
  auto start = const_cast<char *>(reinterpret_cast<const char *>(page));
  __builtin___clear_cache(start, start + mem_page_size);
}

#endif // end of __APPLE__

constexpr const std::string_view cppm_init_func = "ZGIW3std";

static inline void page_writable(const void *page) {
  mprotect(const_cast<void *>(page), mem_page_size, PROT_WRITE);
}

static inline void page_executable(const void *page) {
  mprotect(const_cast<void *>(page), mem_page_size, PROT_READ | PROT_EXEC);
}

extern "C" {
int __cxa_atexit(void (*f)(void *), void *p, void *d);
void __cxa_throw(void *thrown_object, std::type_info *tinfo,
                 void (*dest)(void *));
void __stack_chk_fail(void);
}

#endif // end of ON_WINDOWS

const void *load_library(std::string_view path);

// the symbol name must be in raw format which is exactly parsed from
// the object file
const void *find_symbol(const void *handle, std::string_view raw);

void iterate_modules(
    const std::function<bool(uint64_t base, std::string_view path)> &callback);

} // namespace icpp
