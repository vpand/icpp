//===-- POSIX header dirent.h ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_DIRENT_H
#define LLVM_LIBC_DIRENT_H

#include "__llvm-libc-common.h"

#include <llvm-libc-types/struct_dirent.h>
#include <llvm-libc-types/DIR.h>
#include <llvm-libc-types/ino_t.h>

__BEGIN_C_DECLS

int closedir(DIR *) __NOEXCEPT;

int dirfd(DIR *) __NOEXCEPT;

DIR * opendir(const char *) __NOEXCEPT;

struct dirent * readdir(DIR *) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_DIRENT_H
