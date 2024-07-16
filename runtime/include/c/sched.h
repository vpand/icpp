//===-- C standard library header sched.h ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SCHED_H
#define LLVM_LIBC_SCHED_H

#include "__llvm-libc-common.h"
#include "llvm-libc-macros/sched-macros.h"

#include <llvm-libc-types/struct_timespec.h>
#include <llvm-libc-types/cpu_set_t.h>
#include <llvm-libc-types/time_t.h>
#include <llvm-libc-types/size_t.h>
#include <llvm-libc-types/struct_sched_param.h>
#include <llvm-libc-types/pid_t.h>

__BEGIN_C_DECLS

int sched_get_priority_max(int) __NOEXCEPT;

int sched_get_priority_min(int) __NOEXCEPT;

int sched_getaffinity(pid_t, size_t, cpu_set_t *) __NOEXCEPT;

int sched_getparam(pid_t, struct sched_param *) __NOEXCEPT;

int sched_getscheduler(pid_t, int, const struct sched_param *) __NOEXCEPT;

int sched_rr_get_interval(pid_t, struct timespec *) __NOEXCEPT;

int sched_setaffinity(pid_t, size_t, const cpu_set_t *) __NOEXCEPT;

int sched_setparam(pid_t, const struct sched_param *) __NOEXCEPT;

int sched_setscheduler(pid_t) __NOEXCEPT;

int sched_yield(void) __NOEXCEPT;

int __sched_getcpucount(size_t, const cpu_set_t *) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SCHED_H
