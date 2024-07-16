//===-- C standard library header fenv.h ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_FENV_H
#define LLVM_LIBC_FENV_H

#include "__llvm-libc-common.h"
#include "llvm-libc-macros/fenv-macros.h"

#include <llvm-libc-types/fexcept_t.h>
#include <llvm-libc-types/fenv_t.h>

__BEGIN_C_DECLS

int feclearexcept(int) __NOEXCEPT;

int fedisableexcept(int) __NOEXCEPT;

int feenableexcept(int) __NOEXCEPT;

int fegetenv(fenv_t *) __NOEXCEPT;

int fegetexcept() __NOEXCEPT;

int fegetexceptflag(fexcept_t *, int) __NOEXCEPT;

int fegetround() __NOEXCEPT;

int feholdexcept(fenv_t *) __NOEXCEPT;

int fesetenv(const fenv_t *) __NOEXCEPT;

int fesetexcept(int) __NOEXCEPT;

int fesetexceptflag(const fexcept_t *, int) __NOEXCEPT;

int fesetround(int) __NOEXCEPT;

int feraiseexcept(int) __NOEXCEPT;

int fetestexcept(int) __NOEXCEPT;

int fetestexceptflag(const fexcept_t *, int) __NOEXCEPT;

int feupdateenv(const fenv_t *) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_FENV_H
