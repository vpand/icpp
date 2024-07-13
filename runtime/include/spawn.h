//===-- POSIX header spawn.h ----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SPAWN_H
#define LLVM_LIBC_SPAWN_H

#include "__llvm-libc-common.h"

#include <llvm-libc-types/posix_spawn_file_actions_t.h>
#include <llvm-libc-types/posix_spawnattr_t.h>
#include <llvm-libc-types/pid_t.h>
#include <llvm-libc-types/mode_t.h>

__BEGIN_C_DECLS

int posix_spawn(pid_t *__restrict, const char *__restrict, posix_spawn_file_actions_t *, posix_spawnattr_t *__restrict, const char *__restrict *, const char *__restrict *) __NOEXCEPT;

int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *, int) __NOEXCEPT;

int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *, int, int) __NOEXCEPT;

int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *__restrict, int, const char *__restrict, int, mode_t) __NOEXCEPT;

int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *) __NOEXCEPT;

int posix_spawn_file_actions_init(posix_spawn_file_actions_t *) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_SPAWN_H
