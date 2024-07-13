//===-- C standard library header threads.h -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_THREADS_H
#define LLVM_LIBC_THREADS_H

#include "__llvm-libc-common.h"

#define ONCE_FLAG_INIT {0}

#include <llvm-libc-types/thrd_t.h>
#include <llvm-libc-types/mtx_t.h>
#include <llvm-libc-types/tss_dtor_t.h>
#include <llvm-libc-types/tss_t.h>
#include <llvm-libc-types/cnd_t.h>
#include <llvm-libc-types/once_flag.h>
#include <llvm-libc-types/thrd_start_t.h>
#include <llvm-libc-types/__call_once_func_t.h>

enum {
  thrd_nomem,
  thrd_error,
  thrd_busy,
  thrd_success,
  thrd_timedout,
  mtx_recursive,
  mtx_timed,
  mtx_plain,
};

__BEGIN_C_DECLS

void call_once(once_flag *, __call_once_func_t) __NOEXCEPT;

int cnd_broadcast(cnd_t *) __NOEXCEPT;

void cnd_destroy(cnd_t *) __NOEXCEPT;

int cnd_init(cnd_t *) __NOEXCEPT;

int cnd_signal(cnd_t *) __NOEXCEPT;

int cnd_wait(cnd_t *, mtx_t *) __NOEXCEPT;

int mtx_destroy(void) __NOEXCEPT;

int mtx_init(mtx_t *, int) __NOEXCEPT;

int mtx_lock(mtx_t *) __NOEXCEPT;

int mtx_unlock(mtx_t *) __NOEXCEPT;

int thrd_create(thrd_t *, thrd_start_t, void *) __NOEXCEPT;

thrd_t thrd_current(void) __NOEXCEPT;

int thrd_detach(thrd_t) __NOEXCEPT;

int thrd_equal(thrd_t, thrd_t) __NOEXCEPT;

void thrd_exit(int) __NOEXCEPT;

int thrd_join(thrd_t, int *) __NOEXCEPT;

int tss_create(tss_t *, tss_dtor_t) __NOEXCEPT;

int tss_delete(tss_t) __NOEXCEPT;

void * tss_get(tss_t) __NOEXCEPT;

int tss_set(tss_t, void *) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_THREADS_H
