/* Interpreting C++, executing the source and executable like a script */
/* By Jesse Liu < neoliu2011@gmail.com >, 2024 */
/* Copyright (c) vpand.com 2024. This file is released under LGPL2.
   See LICENSE in root directory for more details
*/

#pragma once

#include <functional>
#include <string_view>

#if defined(_WIN32) || defined(_WIN64)
#define ON_WINDOWS 1
#else
#define ON_UNIX 1
#endif

#if ON_WINDOWS
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>

#define __ICPP_EXPORT__ __declspec(dllexport)
#else
#include <dlfcn.h>
#include <pthread.h>
#if __APPLE__
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#endif

#define __ICPP_EXPORT__ __attribute__((visibility("default")))
#endif // end of ON_WINDOWS

namespace icpp {

#ifdef ON_WINDOWS

#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>

typedef HANDLE (*thread_create_t)(
    [ in, optional ] LPSECURITY_ATTRIBUTES lpThreadAttributes,
    [in] SIZE_T dwStackSize, [in] LPTHREAD_START_ROUTINE lpStartAddress,
    [ in, optional ] __drv_aliasesMem LPVOID lpParameter,
    [in] DWORD dwCreationFlags, [ out, optional ] LPDWORD lpThreadId);

typedef DWORD thread_return_t;

constexpr const thread_create_t thread_create = CreateThread;
constexpr const std::string_view env_home = "userprofile";
constexpr const std::string_view path_split = ";";
constexpr const std::string_view ndk_build = "ndk-build.bat";

#else

typedef int (*thread_create_t)(pthread_t *thread, const pthread_attr_t *attr,
                               void *(*start_routine)(void *), void *arg);
typedef void *thread_return_t;

constexpr const thread_create_t thread_create = pthread_create;
constexpr const std::string_view env_home = "HOME";
constexpr const std::string_view path_split = ":";
constexpr const std::string_view ndk_build = "ndk-build";

#endif

const void *load_library(std::string_view path);

// the symbol name must be in raw format which is exactly parsed from
// the object file
const void *find_symbol(const void *handle, std::string_view raw);

void iterate_modules(
    const std::function<void(uint64_t base, std::string_view path)> &callback);

std::vector<std::string> extra_cflags();

} // namespace icpp
