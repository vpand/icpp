//===-- C standard library header ctype.h --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_CTYPE_H
#define LLVM_LIBC_CTYPE_H

#include "__llvm-libc-common.h"


__BEGIN_C_DECLS

int isalnum(int) __NOEXCEPT;

int isalpha(int) __NOEXCEPT;

int isascii(int) __NOEXCEPT;

int isblank(int) __NOEXCEPT;

int iscntrl(int) __NOEXCEPT;

int isdigit(int) __NOEXCEPT;

int isgraph(int) __NOEXCEPT;

int islower(int) __NOEXCEPT;

int isprint(int) __NOEXCEPT;

int ispunct(int) __NOEXCEPT;

int isspace(int) __NOEXCEPT;

int isupper(int) __NOEXCEPT;

int isxdigit(int) __NOEXCEPT;

int toascii(int) __NOEXCEPT;

int tolower(int) __NOEXCEPT;

int toupper(int) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_CTYPE_H
