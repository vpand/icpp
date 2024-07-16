//===-- POSIX header stat.h -----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SYS_STAT_H
#define LLVM_LIBC_SYS_STAT_H

#include "__llvm-libc-common.h"

#include "llvm-libc-macros/sys-stat-macros.h"

#include <llvm-libc-types/struct_stat.h>
#include <llvm-libc-types/nlink_t.h>
#include <llvm-libc-types/blkcnt_t.h>
#include <llvm-libc-types/struct_timespec.h>
#include <llvm-libc-types/dev_t.h>
#include <llvm-libc-types/gid_t.h>
#include <llvm-libc-types/blksize_t.h>
#include <llvm-libc-types/uid_t.h>
#include <llvm-libc-types/struct_timeval.h>
#include <llvm-libc-types/ino_t.h>
#include <llvm-libc-types/off_t.h>
#include <llvm-libc-types/mode_t.h>

__BEGIN_C_DECLS

int chmod(const char *, mode_t) __NOEXCEPT;

int fchmod(int, mode_t) __NOEXCEPT;

int fchmodat(int, const char *, mode_t, int) __NOEXCEPT;

int fstat(int, struct stat *) __NOEXCEPT;

int lstat(const char *__restrict, struct stat *__restrict) __NOEXCEPT;

int mkdir(const char *, mode_t) __NOEXCEPT;

int mkdirat(int, const char *, mode_t) __NOEXCEPT;

int stat(const char *__restrict, struct stat *__restrict) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SYS_STAT_H
