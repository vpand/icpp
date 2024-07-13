//===-- Linux sys/select.h ------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SYS_SELECT_H
#define LLVM_LIBC_SYS_SELECT_H

#include "__llvm-libc-common.h"

#include "llvm-libc-macros/sys-select-macros.h"

#include <llvm-libc-types/time_t.h>
#include <llvm-libc-types/struct_timespec.h>
#include <llvm-libc-types/suseconds_t.h>
#include <llvm-libc-types/struct_timeval.h>
#include <llvm-libc-types/sigset_t.h>
#include <llvm-libc-types/fd_set.h>

__BEGIN_C_DECLS

int select(int, fd_set *__restrict, fd_set *__restrict, fd_set *__restrict, struct timeval *__restrict) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SYS_SELECT_H
