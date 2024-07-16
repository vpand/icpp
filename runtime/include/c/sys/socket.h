//===-- POSIX header sys/socket.h -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SYS_SOCKET_H
#define LLVM_LIBC_SYS_SOCKET_H

#include "__llvm-libc-common.h"

#include "llvm-libc-macros/sys-socket-macros.h"

#include <llvm-libc-types/struct_sockaddr_un.h>
#include <llvm-libc-types/struct_sockaddr.h>
#include <llvm-libc-types/socklen_t.h>
#include <llvm-libc-types/sa_family_t.h>

__BEGIN_C_DECLS

int socket(int, int, int) __NOEXCEPT;

int bind(int, const struct sockaddr *, socklen_t) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SYS_SOCKET_H
