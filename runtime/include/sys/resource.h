//===-- POSIX header resource.h -------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SYS_RESOURCE_H
#define LLVM_LIBC_SYS_RESOURCE_H

#include "__llvm-libc-common.h"

#include "llvm-libc-macros/sys-resource-macros.h"

#include <llvm-libc-types/struct_rlimit.h>
#include <llvm-libc-types/rlim_t.h>

__BEGIN_C_DECLS

int getrlimit(struct rlimit *) __NOEXCEPT;

int setrlimit(const struct rlimit) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SYS_RESOURCE_H
