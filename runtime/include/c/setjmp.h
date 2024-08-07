//===-- C standard library header setjmp.h --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SETJMP_H
#define LLVM_LIBC_SETJMP_H

#include "__llvm-libc-common.h"

#include <llvm-libc-types/jmp_buf.h>

__BEGIN_C_DECLS

void longjmp(jmp_buf, int) __NOEXCEPT;

int setjmp(jmp_buf) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SETJMP_H
