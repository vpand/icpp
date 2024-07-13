//===-- Definition of type div_t ------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_TYPES_DIV_T_H
#define LLVM_LIBC_TYPES_DIV_T_H

typedef struct {
  int quot;
  int rem;
} div_t;

#endif // LLVM_LIBC_TYPES_DIV_T_H
