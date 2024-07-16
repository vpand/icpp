//===-- Linux header epoll.h ----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SYS_EPOLL_H
#define LLVM_LIBC_SYS_EPOLL_H

#include "__llvm-libc-common.h"

#include "llvm-libc-macros/sys-epoll-macros.h"

#include <llvm-libc-types/struct_timespec.h>
#include <llvm-libc-types/sigset_t.h>
#include <llvm-libc-types/struct_epoll_data.h>
#include <llvm-libc-types/struct_epoll_event.h>

__BEGIN_C_DECLS

int epoll_create(int) __NOEXCEPT;

int epoll_create1(int) __NOEXCEPT;

int epoll_ctl(int, int, int, struct epoll_event *) __NOEXCEPT;

int epoll_wait(int, struct epoll_event *, int, int) __NOEXCEPT;

int epoll_pwait(int, struct epoll_event *, int, int, sigset_t *) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SYS_EPOLL_H
