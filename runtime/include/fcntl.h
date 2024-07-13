//===-- C standard library header fcntl.h ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_FCNTL_H
#define LLVM_LIBC_FCNTL_H

#include "__llvm-libc-common.h"
#include "llvm-libc-macros/fcntl-macros.h"

#include <llvm-libc-types/off_t.h>
#include <llvm-libc-types/mode_t.h>

__BEGIN_C_DECLS

int creat(const char *, mode_t) __NOEXCEPT;

int fcntl(int, int, ...) __NOEXCEPT;

int open(const char *, int, ...) __NOEXCEPT;

int openat(int, const char *, int, ...) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_FCNTL_H
