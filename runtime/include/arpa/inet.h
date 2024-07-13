//===-- C standard library header network.h -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_ARPA_INET_H
#define LLVM_LIBC_ARPA_INET_H

#include "__llvm-libc-common.h"

#include <inttypes.h>


__BEGIN_C_DECLS

uint32_t htonl(uint32_t) __NOEXCEPT;

uint16_t htons(uint16_t) __NOEXCEPT;

uint32_t ntohl(uint32_t) __NOEXCEPT;

uint16_t ntohs(uint16_t) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_ARPA_INET_H
