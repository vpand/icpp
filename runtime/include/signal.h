//===-- C standard library header signal.h --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SIGNAL_H
#define LLVM_LIBC_SIGNAL_H

#include "__llvm-libc-common.h"

#define __need_size_t
#include <stddef.h>

#include "llvm-libc-macros/signal-macros.h"

#include <llvm-libc-types/pid_t.h>
#include <llvm-libc-types/stack_t.h>
#include <llvm-libc-types/siginfo_t.h>
#include <llvm-libc-types/union_sigval.h>
#include <llvm-libc-types/struct_sigaction.h>
#include <llvm-libc-types/sigset_t.h>
#include <llvm-libc-types/sig_atomic_t.h>

__BEGIN_C_DECLS

int raise(int) __NOEXCEPT;

int kill(pid_t, int) __NOEXCEPT;

int sigaction(int, const struct sigaction *__restrict, struct sigaction *__restrict) __NOEXCEPT;

int sigaltstack(const stack_t *__restrict, stack_t *__restrict) __NOEXCEPT;

int sigdelset(sigset_t *, int) __NOEXCEPT;

int sigaddset(sigset_t *, int) __NOEXCEPT;

int sigemptyset(sigset_t *) __NOEXCEPT;

int sigprocmask(int, const sigset_t *__restrict, sigset_t *__restrict) __NOEXCEPT;

int sigfillset(sigset_t *) __NOEXCEPT;

__sighandler_t signal(int, __sighandler_t) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SIGNAL_H
