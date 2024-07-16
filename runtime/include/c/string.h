//===-- C standard library header string.h --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_STRING_H
#define LLVM_LIBC_STRING_H

#include "__llvm-libc-common.h"

#include "llvm-libc-macros/null-macro.h"

#include <llvm-libc-types/size_t.h>

__BEGIN_C_DECLS

void * memccpy(void *__restrict, const void *__restrict, int, size_t) __NOEXCEPT;

void * memchr(const void *, int, size_t) __NOEXCEPT;

int memcmp(const void *, const void *, size_t) __NOEXCEPT;

void * memcpy(void *__restrict, const void *__restrict, size_t) __NOEXCEPT;

void * memmem(const void *, size_t, const void *, size_t) __NOEXCEPT;

void * memmove(void *, const void *, size_t) __NOEXCEPT;

void * mempcpy(void *__restrict, const void *__restrict, size_t) __NOEXCEPT;

void * memrchr(const void *, int, size_t) __NOEXCEPT;

void * memset(void *, int, size_t) __NOEXCEPT;

void * memset_explicit(void *, int, size_t) __NOEXCEPT;

char * stpcpy(char *__restrict, const char *__restrict) __NOEXCEPT;

char * stpncpy(char *__restrict, const char *__restrict, size_t) __NOEXCEPT;

char * strcasestr(const char *, const char *) __NOEXCEPT;

char * strcat(char *__restrict, const char *__restrict) __NOEXCEPT;

char * strchr(const char *, int) __NOEXCEPT;

char * strchrnul(const char *, int) __NOEXCEPT;

int strcmp(const char *, const char *) __NOEXCEPT;

int strcoll(const char *, const char *) __NOEXCEPT;

char * strcpy(char *__restrict, const char *__restrict) __NOEXCEPT;

size_t strcspn(const char *, const char *) __NOEXCEPT;

char * strdup(const char *) __NOEXCEPT;

char * strerror(int) __NOEXCEPT;

char * strerror_r(int, char *, size_t) __NOEXCEPT;

size_t strlcat(const char *__restrict, const char *__restrict, size_t) __NOEXCEPT;

size_t strlcpy(const char *__restrict, const char *__restrict, size_t) __NOEXCEPT;

size_t strlen(const char *) __NOEXCEPT;

char * strncat(char *, const char *, size_t) __NOEXCEPT;

int strncmp(const char *, const char *, size_t) __NOEXCEPT;

char * strncpy(char *__restrict, const char *__restrict, size_t) __NOEXCEPT;

char * strndup(const char *, size_t) __NOEXCEPT;

size_t strnlen(const char *, size_t) __NOEXCEPT;

char * strpbrk(const char *, const char *) __NOEXCEPT;

char * strrchr(const char *, int) __NOEXCEPT;

char * strsep(char * *__restrict, const char *__restrict) __NOEXCEPT;

char * strsignal(int) __NOEXCEPT;

size_t strspn(const char *, const char *) __NOEXCEPT;

char * strstr(const char *, const char *) __NOEXCEPT;

char * strtok(char *__restrict, const char *__restrict) __NOEXCEPT;

char * strtok_r(char *__restrict, const char *__restrict, char * *__restrict) __NOEXCEPT;

size_t strxfrm(char *__restrict, const char *__restrict, size_t) __NOEXCEPT;

__END_C_DECLS

#endif // LLVM_LIBC_STRING_H
