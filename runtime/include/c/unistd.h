//===-- C standard library header unistd.h --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_UNISTD_H
#define LLVM_LIBC_UNISTD_H

#include "__llvm-libc-common.h"
#include "llvm-libc-macros/file-seek-macros.h"
#include "llvm-libc-macros/unistd-macros.h"

#include <llvm-libc-types/__getoptargv_t.h>
#include <llvm-libc-types/uid_t.h>
#include <llvm-libc-types/size_t.h>
#include <llvm-libc-types/ssize_t.h>
#include <llvm-libc-types/off_t.h>
#include <llvm-libc-types/__exec_envp_t.h>
#include <llvm-libc-types/pid_t.h>
#include <llvm-libc-types/__exec_argv_t.h>

__BEGIN_C_DECLS

int access(const char *, int) __NOEXCEPT;

int chdir(const char *) __NOEXCEPT;

int close(int) __NOEXCEPT;

int dup(int) __NOEXCEPT;

int dup2(int, int) __NOEXCEPT;

int dup3(int, int, int) __NOEXCEPT;

int execve(const char *, __exec_argv_t, __exec_envp_t) __NOEXCEPT;

int fchdir(int) __NOEXCEPT;

int fsync(int) __NOEXCEPT;

int ftruncate(int, off_t) __NOEXCEPT;

char * getcwd(char *, size_t) __NOEXCEPT;

uid_t geteuid(void) __NOEXCEPT;

int getpid(void) __NOEXCEPT;

int getppid(void) __NOEXCEPT;

uid_t getuid(void) __NOEXCEPT;

int isatty(int) __NOEXCEPT;

int link(const char *, const char *) __NOEXCEPT;

int linkat(int, const char *, int, const char *, int) __NOEXCEPT;

off_t lseek(int, off_t, int) __NOEXCEPT;

int pipe(int *) __NOEXCEPT;

ssize_t pread(int, void *, size_t, off_t) __NOEXCEPT;

ssize_t pwrite(int, const void *, size_t, off_t) __NOEXCEPT;

ssize_t read(int, void *, size_t) __NOEXCEPT;

ssize_t readlink(const char *__restrict, char *__restrict, size_t) __NOEXCEPT;

ssize_t readlinkat(const char *__restrict, char *__restrict, size_t) __NOEXCEPT;

int rmdir(const char *) __NOEXCEPT;

int symlink(const char *, const char *) __NOEXCEPT;

int symlinkat(int, const char *, int, const char *) __NOEXCEPT;

int sysconf(int) __NOEXCEPT;

int truncate(const char *, off_t) __NOEXCEPT;

int unlink(const char *) __NOEXCEPT;

int unlinkat(int, const char *, int) __NOEXCEPT;

ssize_t write(int, const void *, size_t) __NOEXCEPT;

_Noreturn void _exit(int) __NOEXCEPT;

int execv(const char *, __exec_argv_t) __NOEXCEPT;

pid_t fork(void) __NOEXCEPT;

long __llvm_libc_syscall(long, long, long, long, long, long, long) __NOEXCEPT;

int getopt(int, __getoptargv_t, const char *) __NOEXCEPT;

void swab(const void *__restrict, void *, ssize_t) __NOEXCEPT;

extern char ** environ;
extern char * optarg;
extern int optind;
extern int optopt;
extern int opterr;
__END_C_DECLS

#endif // LLVM_LIBC_UNISTD_H
