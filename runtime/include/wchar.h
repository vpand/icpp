//===-- C standard library header wchar.h ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_WCHAR_H
#define LLVM_LIBC_WCHAR_H

#include "__llvm-libc-common.h"
#include "llvm-libc-macros/wchar-macros.h"

#include <llvm-libc-types/size_t.h>
#include <llvm-libc-types/wint_t.h>
#include <llvm-libc-types/wchar_t.h>

__BEGIN_C_DECLS

int wctob(wint_t) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_WCHAR_H
