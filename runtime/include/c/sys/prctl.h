//===-- Linux header prctl.h ----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SYS_PRCTL_H
#define LLVM_LIBC_SYS_PRCTL_H

#include "__llvm-libc-common.h"

// Process control is highly platform specific, so the platform usually defines
// the macros itself.
#include <linux/prctl.h>


__BEGIN_C_DECLS

__END_C_DECLS

#endif // LLVM_LIBC_SYS_PRCTL_H
