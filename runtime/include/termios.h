//===-- C standard library header termios.h -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_TERMIOS_H
#define LLVM_LIBC_TERMIOS_H

#include "__llvm-libc-common.h"
#include "llvm-libc-macros/termios-macros.h"

#include <llvm-libc-types/tcflag_t.h>
#include <llvm-libc-types/pid_t.h>
#include <llvm-libc-types/struct_termios.h>
#include <llvm-libc-types/speed_t.h>
#include <llvm-libc-types/cc_t.h>

__BEGIN_C_DECLS

speed_t cfgetispeed(const struct termios *) __NOEXCEPT;

speed_t cfgetospeed(const struct termios *) __NOEXCEPT;

speed_t cfsetispeed(struct termios *, speed_t) __NOEXCEPT;

speed_t cfsetospeed(struct termios *, speed_t) __NOEXCEPT;

int tcgetattr(int, struct termios *) __NOEXCEPT;

pid_t tcgetsid(int) __NOEXCEPT;

int tcdrain(int) __NOEXCEPT;

int tcflow(int, int) __NOEXCEPT;

int tcflush(int, int) __NOEXCEPT;

int tcsendbreak(int, int) __NOEXCEPT;

int tcsetattr(int, int, struct termios *) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_TERMIOS_H
