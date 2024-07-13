//===-- Linux sys/random.h ------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SYS_RANDOM_H
#define LLVM_LIBC_SYS_RANDOM_H

#include "__llvm-libc-common.h"

#include "llvm-libc-macros/sys-random-macros.h"

#include <llvm-libc-types/ssize_t.h>
#include <llvm-libc-types/size_t.h>

__BEGIN_C_DECLS

ssize_t getrandom(void *, size_t, unsigned int) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SYS_RANDOM_H
