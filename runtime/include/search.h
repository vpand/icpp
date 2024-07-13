//===-- POSIX header search.h ---------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SEARCH_H
#define LLVM_LIBC_SEARCH_H

#include "__llvm-libc-common.h"
#define __need_size_t
#include <stddef.h>

#include <llvm-libc-types/struct_hsearch_data.h>
#include <llvm-libc-types/ENTRY.h>
#include <llvm-libc-types/ACTION.h>

__BEGIN_C_DECLS

int hcreate(size_t) __NOEXCEPT;

int hcreate_r(size_t, struct hsearch_data *) __NOEXCEPT;

ENTRY * hsearch(ENTRY, ACTION) __NOEXCEPT;

int hsearch_r(ENTRY, ACTION, ENTRY * *, struct hsearch_data *) __NOEXCEPT;

void hdestroy() __NOEXCEPT;

void hdestroy_r(struct hsearch_data *) __NOEXCEPT;

void insque(void *, void *) __NOEXCEPT;

void remque(void *) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SEARCH_H
